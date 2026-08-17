package kbpf

import (
	"strings"
	"testing"
	"unsafe"
)

// O LAYOUT é a parte que 32 bits quebra em silêncio.
//
// A bpf_attr do kernel declara todo endereço como __aligned_u64: oito bytes,
// alinhados em oito, INDEPENDENTE da arquitetura. Em Go, um ponteiro tem quatro
// bytes num host de 32 bits — e uma struct montada ingenuamente fica com os
// campos seguintes deslocados. O kernel então lê o campo errado, a chamada
// falha ou devolve outra coisa, e nada disso quebra a compilação.
//
// É o mesmo eixo do FS_IOC_GETFLAGS, que já mordeu este projeto: o número
// dependia do tamanho de `long` e a leitura teria mentido em i686. Aqui o teste
// trava os tamanhos, e ele roda em toda arquitetura que a suíte cruza.
func TestLayoutDaBpfAttr(t *testing.T) {
	if n := unsafe.Sizeof(ponteiro64{}); n != 8 {
		t.Fatalf("ponteiro64 tem %d bytes: o kernel exige 8 em qualquer arquitetura", n)
	}
	casos := []struct {
		nome string
		got  uintptr
		quer uintptr
	}{
		{"BPF_*_GET_NEXT_ID", unsafe.Sizeof(attrProximoID{}), 12},
		{"BPF_*_GET_FD_BY_ID", unsafe.Sizeof(attrFDPorID{}), 12},
		{"BPF_OBJ_GET_INFO_BY_FD", unsafe.Sizeof(attrInfo{}), 16},
		{"BPF_OBJ_GET", unsafe.Sizeof(attrObjGet{}), 16},
		{"BPF_MAP_LOOKUP_ELEM", unsafe.Sizeof(attrLookup{}), 32},
		{"BPF_TASK_FD_QUERY", unsafe.Sizeof(attrTaskFDQuery{}), 48},
	}
	for _, c := range casos {
		if c.got != c.quer {
			t.Errorf("%s: %d bytes, o kernel espera %d", c.nome, c.got, c.quer)
		}
	}
	// Os deslocamentos dos campos que o kernel LÊ e ESCREVE.
	if o := unsafe.Offsetof(attrInfo{}.info); o != 8 {
		t.Errorf("attrInfo.info em %d, o kernel espera 8", o)
	}
	if o := unsafe.Offsetof(attrObjGet{}.fd); o != 8 {
		t.Errorf("attrObjGet.fd em %d, o kernel espera 8", o)
	}
	if o := unsafe.Offsetof(attrLookup{}.valor); o != 16 {
		t.Errorf("attrLookup.valor em %d, o kernel espera 16", o)
	}
	if o := unsafe.Offsetof(attrTaskFDQuery{}.progID); o != 24 {
		t.Errorf("attrTaskFDQuery.progID em %d, o kernel espera 24", o)
	}
}

// Kernel antigo devolve uma struct MENOR, e ele diz o tamanho de volta. Ler
// além disso não é ler zero: é ler o que sobrou do buffer, e um campo
// inventado aqui vira data de carga inventada no relatório.
func TestLeitorNaoPassaDoQueOKernelPreencheu(t *testing.T) {
	buf := make([]byte, 64)
	for i := range buf {
		buf[i] = 0xff // se algum leitor passar do limite, vem lixo reconhecível
	}
	le.PutUint32(buf[0:], 5)
	le.PutUint32(buf[4:], 47)

	const preenchido = 8
	if v := u32(buf, preenchido, 0); v != 5 {
		t.Errorf("tipo = %d, queria 5", v)
	}
	if v := u32(buf, preenchido, 4); v != 47 {
		t.Errorf("id = %d, queria 47", v)
	}
	if v := u32(buf, preenchido, 8); v != 0 {
		t.Errorf("campo além do preenchido devolveu %d: tinha que ser zero", v)
	}
	if v := u64(buf, preenchido, 40); v != 0 {
		t.Errorf("load_time além do preenchido devolveu %d", v)
	}
	if s := cstr(buf, preenchido, 64, 16); s != "" {
		t.Errorf("nome além do preenchido devolveu %q", s)
	}
	if s := hexOu(buf, preenchido, 8, 8); s != "" {
		t.Errorf("tag além do preenchido devolveu %q", s)
	}
}

func TestLeitoresDecodificamOFormatoDoKernel(t *testing.T) {
	buf := make([]byte, 96)
	copy(buf[8:16], []byte{0xa0, 0x4f, 0x5e, 0xef, 0x06, 0xa7, 0xf5, 0x55})
	copy(buf[64:80], "sys_enter\x00lixo")

	if got := hexOu(buf, 96, 8, 8); got != "a04f5eef06a7f555" {
		t.Errorf("tag = %q", got)
	}
	// O nome tem 16 bytes de campo e termina em NUL: o resto do campo não faz
	// parte dele.
	if got := cstr(buf, 96, 64, 16); got != "sys_enter" {
		t.Errorf("nome = %q", got)
	}
}

// Tipo que este binário não conhece é kernel mais NOVO que ele. A resposta é o
// número, nunca um palpite — e, mais importante, a fixação vira DESCONHECIDA,
// que é o que impede o check de acusar o que não sabe interpretar.
func TestTipoDesconhecidoNaoViraPalpite(t *testing.T) {
	if got := TipoPrograma(9999); got != "tipo_9999" {
		t.Errorf("TipoPrograma(9999) = %q", got)
	}
	if got := TipoLink(9999); got != "link_9999" {
		t.Errorf("TipoLink(9999) = %q", got)
	}
	if got := FixacaoDe(9999); got != FixDesconhecida {
		t.Errorf("FixacaoDe(9999) = %v, queria FixDesconhecida", got)
	}
	if Intercepta(9999) {
		t.Error("tipo desconhecido não pode ser tratado como interceptador")
	}
	if m := FixDesconhecida.Motivo(); !strings.Contains(m, "não conhece") {
		t.Errorf("o motivo precisa dizer que o binário não conhece o tipo: %q", m)
	}
}

// A classificação de fixação é o que separa achado de lacuna declarada. Errar
// para o lado de FixVisivel produz achado em todo host com cilium; errar para o
// outro lado cala o check.
func TestFixacaoPorFamilia(t *testing.T) {
	casos := []struct {
		tipo uint32
		quer Fixacao
	}{
		{ProgKprobe, FixVisivel},
		{ProgTracing, FixVisivel},
		{ProgLSM, FixVisivel},
		{ProgSocketFilter, FixSocket},
		{ProgSkReuseport, FixSocket},
		{ProgSchedCls, FixNetlink},
		{ProgXDP, FixNetlink},
		{ProgCgroupDevice, FixCgroup},
		{ProgStructOps, FixMapa},
	}
	for _, c := range casos {
		if got := FixacaoDe(c.tipo); got != c.quer {
			t.Errorf("FixacaoDe(%s) = %v, queria %v", TipoPrograma(c.tipo), got, c.quer)
		}
	}
	// Só FixVisivel promete que o detentor é legível; todas as outras precisam
	// explicar por que não é.
	for _, f := range []Fixacao{FixSocket, FixNetlink, FixCgroup, FixMapa, FixDesconhecida} {
		if f.Motivo() == "" {
			t.Errorf("fixação %v sem motivo escrito", f)
		}
	}
	if FixVisivel.Motivo() != "" {
		t.Error("FixVisivel não deve ter motivo: o detentor É legível")
	}
}

func TestClasseDeAnonInode(t *testing.T) {
	casos := map[string]string{
		"anon_inode:bpf-prog":     "prog",
		"anon_inode:bpf-map":      "map",
		"anon_inode:bpf-link":     "link",
		"anon_inode:[perf_event]": "",
		"socket:[12345]":          "",
		"/usr/bin/bash":           "",
	}
	for alvo, quer := range casos {
		if got := ClasseDeAnonInode(alvo); got != quer {
			t.Errorf("ClasseDeAnonInode(%q) = %q, queria %q", alvo, got, quer)
		}
	}
}

// Sonda roda contra o kernel de VERDADE desta máquina. Os dois desfechos
// possíveis são legítimos e o teste aceita os dois — o que ele trava é o
// contrato: ou dá certo, ou o motivo sai escrito para o rodapé de cobertura.
func TestSondaOuFuncionaOuExplica(t *testing.T) {
	err := Sonda()
	if err == nil {
		return // rodando como root num kernel moderno
	}
	es, ok := err.(*ErroSonda)
	if !ok {
		t.Fatalf("erro sem classificação: %v", err)
	}
	if len(es.Motivo) < 20 {
		t.Errorf("o motivo vai para o operador e precisa ser uma frase: %q", es.Motivo)
	}
	if es.Errno == 0 {
		t.Error("erro sem errno: quem chama não consegue decidir por ele")
	}
}
