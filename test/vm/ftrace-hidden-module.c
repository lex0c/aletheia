// Módulo de PROVA para test/vm/ftrace-hidden-module.sh. NÃO é malicioso.
//
// Ele existe para responder uma pergunta sobre o kernel: o registro do ftrace
// sobrevive à técnica clássica de ocultação de LKM? Por isso faz o mínimo — se
// desencadeia da lista de módulos, e nada mais.
//
// evil_marcador dá um nome NOSSO em available_filter_functions: toda função
// não-inline de um módulo entra lá automaticamente ao carregar, anotada com o
// nome do módulo entre colchetes.
//
// SEGURANÇA: este .ko só deve ser CARREGADO dentro da VM descartável que o
// script sobe. Nunca com insmod no host nem em contêiner — em contêiner o
// insmod entra no kernel do HOST, e um módulo que se esconde da lista não
// descarrega sem reboot.
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/kobject.h>

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("prova de que o ftrace retem modulo escondido - aletheia");

noinline void evil_marcador(void) { asm volatile(""); }

static int esconder = 0;
module_param(esconder, int, 0);

static int __init evil_init(void)
{
	evil_marcador();
	pr_info("evil: carregado, esconder=%d\n", esconder);
	if (esconder >= 1) {
		// Nível 1 — a técnica clássica: sai da lista encadeada que gera
		// /proc/modules. O registro do ftrace (ftrace_pages) e a árvore de
		// resolução de símbolo (mod_tree) NÃO são tocados aqui — só em
		// free_module.
		list_del(&THIS_MODULE->list);
		pr_info("evil: fora de /proc/modules\n");
	}
	if (esconder >= 2) {
		// Nível 2 — some TAMBÉM de /sys/module. Com os dois, o módulo está
		// escondido das duas interfaces que o crossview clássico compara, e o
		// achado da aletheia só pode vir do ftrace. É o que torna esta a prova
		// forte, e não uma dedução: kobject_del não toca no ftrace tampouco.
		kobject_del(&THIS_MODULE->mkobj.kobj);
		pr_info("evil: fora de /sys/module\n");
	}
	return 0;
}

static void __exit evil_exit(void) { pr_info("evil: descarregado\n"); }

module_init(evil_init);
module_exit(evil_exit);
