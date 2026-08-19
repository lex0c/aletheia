// Módulo de PROVA para test/vm/socket-hidden-module.sh. NÃO é malicioso.
//
// Ele existe para responder uma pergunta sobre o kernel e sobre a ferramenta:
// uma conexão escondida de /proc/net/tcp pela técnica clássica — um hook em
// tcp4_seq_show — continua visível pelo NETLINK_INET_DIAG? E a aletheia,
// rodando DENTRO desse host, transforma isso num achado cross.socket_view?
//
// O módulo faz o mínimo para montar exatamente essa situação:
//
//   1. cria um socket em LISTEN na porta MÁGICA (127.0.0.1:0x1337), de dentro
//      do kernel. Ele aparece em /proc/net/tcp E no inet_diag, como qualquer
//      socket — é o estado LIMPO, em que a aletheia tem de CALAR.
//   2. hooka tcp4_seq_show por ftrace e faz a linha da porta mágica sumir. O
//      inet_diag NÃO passa por tcp4_seq_show, então a porta continua lá — e é
//      esta a divergência que o cross.socket_view existe para pegar.
//
// SEGURANÇA: este .ko só deve ser CARREGADO dentro da VM descartável que o
// script sobe. Nunca com insmod no host nem em contêiner — em contêiner o
// insmod entra no kernel do HOST, e um hook de ftrace em tcp4_seq_show
// esconderia conexão do host inteiro até o descarregamento.
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/ftrace.h>
#include <linux/kprobes.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/seq_file.h>
#include <net/sock.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("prova de que o inet_diag ve conexao escondida de /proc/net/tcp - aletheia");

// 0x1337 = 4919. Em /proc/net/tcp a coluna local aparece como 0100007F:1337.
#define PORTA_MAGICA 0x1337

static int esconder = 0;
module_param(esconder, int, 0);

static struct socket *listener;

// --- resolução de símbolo: kallsyms_lookup_name não é exportado desde o 5.7,
// e o truque do kprobe é a forma padrão de recuperá-lo. ---
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

// --- o hook de ftrace em tcp4_seq_show ---
static asmlinkage int (*real_show)(struct seq_file *, void *);

// dentro marca, POR CPU, que já estamos executando a original a partir do hook.
//
// A guarda ÓBVIA — "o parent_ip está dentro do módulo?" — não funciona em
// kernel com retpoline e IBT: a chamada de volta passa por um thunk indireto no
// CORE do kernel (__x86_indirect_thunk), então o parent nunca parece do módulo,
// o thunk redireciona de novo, e tcp4_seq_show entra em recursão infinita.
// Medido: soft lockup na primeira leitura de /proc/net/tcp.
//
// A flag por CPU não depende de onde o parent está. Com a preempção desligada
// na janela, a re-entrada acontece na MESMA CPU e vê a flag levantada.
static DEFINE_PER_CPU(int, dentro);

// hooked_show decide, por socket, se a linha é impressa. A original imprime UMA
// linha por chamada; não chamá-la é como se aquele socket não existisse para
// quem lê /proc/net/tcp.
static asmlinkage int hooked_show(struct seq_file *seq, void *v)
{
	int r;
	// SEQ_START_TOKEN é o cabeçalho, não um socket: ler porta dele quebraria.
	if (v != SEQ_START_TOKEN) {
		// Todo objeto que o tcp4_seq_show recebe (sock, timewait, request)
		// começa por struct sock_common, então sk_num é seguro de ler.
		struct sock *sk = (struct sock *)v;
		if (sk->sk_num == PORTA_MAGICA)
			return 0; // some de /proc/net/tcp; o inet_diag não passa por aqui
	}
	// tcp4_seq_show só escreve no buffer da seq_file (seq_printf não dorme):
	// desligar a preempção aqui é seguro e é o que garante que a re-entrada
	// caia na mesma CPU que levantou a flag.
	preempt_disable();
	this_cpu_write(dentro, 1);
	r = real_show(seq, v);
	this_cpu_write(dentro, 0);
	preempt_enable();
	return r;
}

static struct ftrace_ops ops;

static void notrace thunk(unsigned long ip, unsigned long parent_ip,
			  struct ftrace_ops *o, struct ftrace_regs *fregs)
{
	struct pt_regs *regs;
	if (this_cpu_read(dentro))
		return; // já estamos na original chamada pelo hook: não redireciona
	regs = ftrace_get_regs(fregs);
	regs->ip = (unsigned long)hooked_show;
}

static int instalar_hook(void)
{
	unsigned long alvo = kln("tcp4_seq_show");
	if (!alvo) {
		pr_err("socket-hidden: tcp4_seq_show não resolvido\n");
		return -1;
	}
	real_show = (void *)alvo;
	ops.func = thunk;
	ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
	if (ftrace_set_filter_ip(&ops, alvo, 0, 0)) {
		pr_err("socket-hidden: ftrace_set_filter_ip falhou\n");
		return -1;
	}
	if (register_ftrace_function(&ops)) {
		pr_err("socket-hidden: register_ftrace_function falhou\n");
		ftrace_set_filter_ip(&ops, alvo, 1, 0);
		return -1;
	}
	return 0;
}

static int criar_listener(void)
{
	struct sockaddr_in addr = {
		.sin_family = AF_INET,
		.sin_port = htons(PORTA_MAGICA),
		.sin_addr.s_addr = htonl(INADDR_LOOPBACK),
	};
	int err = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, IPPROTO_TCP, &listener);
	if (err) {
		pr_err("socket-hidden: sock_create_kern %d\n", err);
		return err;
	}
	err = kernel_bind(listener, (struct sockaddr *)&addr, sizeof(addr));
	if (err) {
		pr_err("socket-hidden: bind %d\n", err);
		return err;
	}
	err = kernel_listen(listener, 16);
	if (err) {
		pr_err("socket-hidden: listen %d\n", err);
		return err;
	}
	pr_info("socket-hidden: LISTEN em 127.0.0.1:%d\n", PORTA_MAGICA);
	return 0;
}

static int __init evil_init(void)
{
	if (criar_listener())
		return -EINVAL;
	if (esconder >= 1) {
		if (resolver_kln() || instalar_hook()) {
			sock_release(listener);
			listener = NULL;
			return -EINVAL;
		}
		pr_info("socket-hidden: porta %d escondida de /proc/net/tcp\n", PORTA_MAGICA);
	}
	return 0;
}

static void __exit evil_exit(void)
{
	if (ops.func)
		unregister_ftrace_function(&ops);
	if (listener)
		sock_release(listener);
	pr_info("socket-hidden: descarregado\n");
}

module_init(evil_init);
module_exit(evil_exit);
