// Módulo de PROVA: um backdoor de netfilter (magic-packet) na forma estrutural
// mínima e SEM comportamento malicioso. Registra um nf_hook em PRE_ROUTING que
// só deixa o pacote passar (NF_ACCEPT) — a estrutura do Syslogk/Drovorub, sem o
// gatilho de pacote.
//
// Existe para MEDIR a cobertura da classe "backdoor de netfilter no kernel". A
// pergunta que ele responde: um hook de netfilter é visto pela Aletheia? O
// kernel NÃO expõe a lista de nf_hooks registrados a userspace
// (/proc/net/netfilter só tem nf_log), então não há como enumerá-los
// nativamente. O que a ferramenta VÊ é o MÓDULO que os registrou — e é essa a
// resposta que este módulo permite medir:
//
//   esconder=0   insmod seguido de rm do .ko -> módulo órfão sem arquivo em
//                disco: kernel.module_no_file deve pegar (como o Z1)
//   esconder=1   o módulo se desencadeia de /proc/modules E /sys/module; a
//                função do hook (nf_backdoor_hook) segue em
//                available_filter_functions, e cross.module_view a delata pela
//                via ftrace (o mesmo mecanismo do modhide)
//
// A conclusão que o cenário afirma: o backdoor de netfilter é pego como MÓDULO
// inexplicado/oculto, não por uma enumeração de hooks que o kernel não oferece.
//
// SEGURANÇA: só deve ser carregado dentro da VM descartável. O hook não altera
// tráfego (NF_ACCEPT sempre), e um módulo que se esconde não descarrega sem
// reboot.
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/list.h>
#include <linux/kobject.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("prova: hook de netfilter visto como modulo - aletheia");

static int esconder = 0;
module_param(esconder, int, 0);

static struct nf_hook_ops ops;

// A função do hook: NÃO-inline, para ter nome próprio em
// available_filter_functions. É por ela que o cross.module_view delata o módulo
// escondido — a mesma via do evil_marcador do modhide.
static unsigned int noinline nf_backdoor_hook(void *priv, struct sk_buff *skb,
					      const struct nf_hook_state *state)
{
	// Um backdoor de verdade compararia o pacote com o gatilho aqui. Este só
	// deixa passar: a estrutura, sem o comportamento.
	return NF_ACCEPT;
}

static int __init nf_init(void)
{
	ops.hook = nf_backdoor_hook;
	ops.pf = NFPROTO_IPV4;
	ops.hooknum = NF_INET_PRE_ROUTING;
	ops.priority = NF_IP_PRI_FIRST;
	if (nf_register_net_hook(&init_net, &ops)) {
		pr_err("nf-hook: registro do hook falhou\n");
		return -EINVAL;
	}
	pr_info("nf-hook: hook de netfilter registrado (esconder=%d)\n", esconder);
	if (esconder >= 1) {
		list_del(&THIS_MODULE->list);          // some de /proc/modules
		kobject_del(&THIS_MODULE->mkobj.kobj); // some de /sys/module
		pr_info("nf-hook: modulo escondido das duas listas\n");
	}
	return 0;
}

static void __exit nf_exit(void)
{
	nf_unregister_net_hook(&init_net, &ops);
	pr_info("nf-hook: hook removido\n");
}

module_init(nf_init);
module_exit(nf_exit);
