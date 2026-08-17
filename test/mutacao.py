#!/usr/bin/env python3
"""Teste de mutação: mede se a suíte TEM DENTES.

Cobertura diz quais linhas foram executadas. Não diz se alguém estava olhando.
Um teste que executa uma linha e não afirma nada sobre ela conta como cobertura
e não protege nada.

A mutação responde a pergunta certa: se eu ESTRAGAR esta decisão, algum teste
reclama? A resposta é um número — quantas mutações SOBREVIVEM —, e sobrevivente
é sempre uma de duas coisas:

    o teste que faltava        a decisão importa e ninguém a afirma
    a decisão que não importa  código que pode ser removido

As duas são achados. A segunda é a mais rara e a mais valiosa.

Uso:  python3 test/mutacao.py [--alvo internal/checks] [--limite 200]
"""

import argparse
import pathlib
import random
import re
import subprocess
import sys
import time

RAIZ = pathlib.Path(__file__).resolve().parent.parent

# As mutações são escolhidas pelo que ESTE código decide, não por catálogo
# genérico. Aqui as decisões são severidade, limiar e guarda — e é nelas que um
# defeito vira falso positivo ou achado perdido.
MUTACOES = [
    # Severidade: rebaixar um crítico é o defeito mais caro que existe nesta
    # ferramenta, porque muda o exit code que a frota lê.
    (r"check\.SevCritical", "check.SevWarn", "crítico rebaixado para aviso"),
    (r"check\.SevWarn\b", "check.SevInfo", "aviso rebaixado para informativo"),
    # Comparação: os limiares separam ruído de achado, e um `>` virando `>=`
    # move a fronteira em um.
    (r"(?<![<>=!])>=(?!=)", ">", "comparação afrouxada: >= virou >"),
    (r"(?<![<>=!])<=(?!=)", "<", "comparação afrouxada: <= virou <"),
    (r"(?<![<>=!])==(?!=)", "!=", "igualdade invertida"),
    # Guarda: `!` numa condição costuma ser a exclusão de um falso positivo.
    (r"if !", "if ", "negação removida da guarda"),
    # Booleano: trocar E por OU alarga toda condição composta.
    (r" && ", " || ", "conjunção virou disjunção"),
]

# Linhas que não valem mutar: comentário, string e declaração de teste.
IGNORAR = re.compile(r"^\s*(//|/\*|\*)")


def sitios(arquivo: pathlib.Path):
    """Devolve (linha, coluna, padrão, troca, descrição) para cada mutação."""
    out = []
    for n, linha in enumerate(arquivo.read_text().split("\n"), 1):
        if IGNORAR.match(linha) or '"' in linha and linha.strip().startswith('"'):
            continue
        for padrao, troca, desc in MUTACOES:
            for m in re.finditer(padrao, linha):
                out.append((n, m.start(), m.end(), troca, desc))
    return out


def aplica(arquivo: pathlib.Path, linha: int, ini: int, fim: int, troca: str) -> str:
    original = arquivo.read_text()
    linhas = original.split("\n")
    l = linhas[linha - 1]
    linhas[linha - 1] = l[:ini] + troca + l[fim:]
    arquivo.write_text("\n".join(linhas))
    return original


def roda_testes(timeout: int, completo: bool) -> bool:
    """True quando a suíte PASSA — ou seja, a mutação sobreviveu.

    Sem `completo`, roda só os testes unitários. É rápido e MEDE MENOS: metade
    da verificação desta base está nos cenários, que executam o binário contra
    contêiner e VM. Uma taxa medida só com unitários subestima, e dizer isso
    importa mais que o número.
    """
    cmds = [["go", "test", "./internal/..."]]
    if completo:
        cmds = [["make", "build"],
                ["go", "test", "-tags", "scenarios", "-count=1", "./test/"]]
    for c in cmds:
        try:
            r = subprocess.run(c, cwd=RAIZ, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            # Mutação que trava o teste é morta: o laço infinito é a reclamação.
            return False
        if r.returncode != 0:
            return False
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alvo", default="internal")
    ap.add_argument("--limite", type=int, default=150)
    ap.add_argument("--semente", type=int, default=1)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--completo", action="store_true",
                    help="roda TAMBÉM a suíte de cenários (lenta, e é onde "
                         "mora metade da verificação)")
    args = ap.parse_args()

    arquivos = [
        p for p in (RAIZ / args.alvo).rglob("*.go")
        if not p.name.endswith("_test.go")
    ]

    todos = []
    for a in arquivos:
        for s in sitios(a):
            todos.append((a, *s))

    # Amostra determinística POR EXECUÇÃO, e só.
    #
    # A semente fixa faz duas execuções sobre o MESMO fonte amostrarem os mesmos
    # sítios. Assim que o fonte muda, os números de linha mudam junto e a
    # amostra deixa de ser a mesma — comparar taxas entre versões diferentes do
    # código compara coisas diferentes, e a primeira versão deste arquivo
    # prometia o contrário.
    random.Random(args.semente).shuffle(todos)
    amostra = todos[: args.limite]

    print(f"{len(todos)} sítios de mutação, testando {len(amostra)}\n")

    sobreviventes = []
    t0 = time.time()
    for i, (arq, linha, ini, fim, troca, desc) in enumerate(amostra, 1):
        original = aplica(arq, linha, ini, fim, troca)
        try:
            sobreviveu = roda_testes(args.timeout, args.completo)
        finally:
            arq.write_text(original)

        rel = arq.relative_to(RAIZ)
        if sobreviveu:
            sobreviventes.append((rel, linha, desc))
            print(f"  SOBREVIVEU  {rel}:{linha}  {desc}")
        if i % 25 == 0:
            print(f"  … {i}/{len(amostra)} ({time.time()-t0:.0f}s)")

    mortas = len(amostra) - len(sobreviventes)
    taxa = 100 * mortas / len(amostra) if amostra else 0
    escopo = "unitários + cenários" if args.completo else "só unitários"
    print(f"\n{mortas}/{len(amostra)} mutações MORTAS ({taxa:.0f}%) — {escopo}")
    print(f"{len(sobreviventes)} sobreviveram — cada uma é um teste que falta "
          f"ou uma decisão que não importa")
    return 0


if __name__ == "__main__":
    sys.exit(main())
