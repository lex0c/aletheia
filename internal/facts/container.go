package facts

import "strings"

// Contêiner: separar "conteúdo de imagem" de "software instalado à mão".
//
// A pergunta central desta ferramenta é "que pacote entregou este binário?", e
// ela não tem resposta útil para o processo de um contêiner. O host VÊ o exe
// dele como um caminho dentro da camada de imagem:
//
//	/var/lib/docker/overlay2/9f3c…/diff/usr/sbin/nginx
//
// Nenhum pacote do host reivindica isso, e a base de pacotes está CERTA — ela
// nunca o entregou. Medido: um servidor com trinta contêineres produzia trinta
// avisos, e contêiner é a norma em produção, não a exceção.
//
// A saída não é suprimir. Escape de contêiner é real, e caminho de imagem é
// exatamente onde um invasor gosta de estar. A saída é DIZER O QUE A COISA É —
// e aí a fonte de ruído vira fonte de sinal, porque duas coisas passam a poder
// se contradizer:
//
//	cgroup diz contêiner + exe em camada de imagem   normal. Sai da pergunta
//	                                                 de propriedade do host
//	cgroup diz HOST      + exe em camada de imagem   alguém executou conteúdo
//	                                                 de imagem FORA do contêiner
//	cgroup diz contêiner + exe fora de toda camada   o processo alcança o
//	                                                 filesystem do host
//
// A classificação é por CGROUP, que é identificação positiva e legível sem
// root — não por padrão de caminho, que o invasor escolhe.

// runtimesDeContainer casa o cgroup com o runtime que o criou. A ordem importa:
// o k8s aparece dentro de escopos do systemd, e o teste dele vem antes.
var runtimesDeContainer = []struct{ marca, runtime string }{
	{"/kubepods", "kubernetes"},
	{"kubepods.slice", "kubernetes"},
	{"/docker-", "docker"},
	{"/docker/", "docker"},
	{"libpod-", "podman"},
	{"/crio-", "cri-o"},
	{"containerd-", "containerd"},
	{"/lxc/", "lxc"},
	{"/lxc.payload", "lxc"},
	{"/machine.slice/machine-", "systemd-nspawn"},
}

// ContainerDoCgroup devolve o runtime e o id curto, ou ("", "") se o cgroup é
// do host.
func ContainerDoCgroup(cg string) (runtime, id string) {
	if cg == "" || cg == "/" {
		return "", ""
	}
	for _, r := range runtimesDeContainer {
		if !strings.Contains(cg, r.marca) {
			continue
		}
		return r.runtime, idDoCgroup(cg)
	}
	return "", ""
}

// idDoCgroup tira o identificador de dentro do caminho. Ele é longo — 64 hex no
// docker — e só os primeiros doze são usados na prática, que é o que o `docker
// ps` mostra.
func idDoCgroup(cg string) string {
	seg := cg
	if i := strings.LastIndexByte(seg, '/'); i >= 0 {
		seg = seg[i+1:]
	}
	seg = strings.TrimSuffix(seg, ".scope")
	seg = strings.TrimSuffix(seg, ".slice")
	for _, p := range []string{"docker-", "libpod-", "crio-", "containerd-", "cri-containerd-"} {
		seg = strings.TrimPrefix(seg, p)
	}
	if len(seg) > 12 && ehHex(seg[:12]) {
		return seg[:12]
	}
	return seg
}

func ehHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return len(s) > 0
}

// raizesDeImagem são as árvores onde os runtimes guardam camada de imagem. Elas
// NÃO classificam processo — quem faz isso é o cgroup —, e servem para a
// pergunta inversa: um exe daqui num processo que o cgroup diz ser do host.
var raizesDeImagem = []string{
	"/var/lib/docker/overlay2/", "/var/lib/docker/aufs/", "/var/lib/docker/btrfs/",
	"/var/lib/docker/devicemapper/", "/var/lib/docker/containers/",
	"/run/containerd/io.containerd.runtime",
	"/var/lib/containers/storage/",
	"/var/lib/lxc/", "/var/lib/machines/",
}

// raizesMistas são as árvores onde o runtime guarda camada de imagem E binário
// do PRÓPRIO HOST, lado a lado. Nelas o prefixo não basta.
//
// O caso que obrigou a distinção é o k3s, e ele não é exótico — é todo nó de
// Kubernetes leve:
//
//	/var/lib/rancher/k3s/data/<hash>/bin/containerd     binário do HOST
//	/var/lib/rancher/k3s/agent/containerd/…/snapshots/N/fs/usr/sbin/nginx
//	                                                   camada de imagem
//
// O primeiro é executado pelo k3s.service, com cgroup /system.slice/k3s.service
// — cgroup de host. Com o prefixo bastando, ele casava a regra "exe em camada de
// imagem + cgroup do host" e saía CRITICAL, sob a frase "não tem caminho
// legítimo comum", em TODO nó k3s e RKE2. Nenhum FalsePositive declarado o
// cobria, e o check é Wtf: true — aparece na triagem de madrugada.
var raizesMistas = []string{"/var/lib/rancher/", "/var/lib/containerd/"}

// marcasDeCamada são os segmentos que só existem dentro de um rootfs de camada:
// o overlay do docker e do podman escreve `diff` e `merged`, o snapshotter do
// containerd põe tudo sob `snapshots/<id>/fs`, e o lxc escreve `rootfs`.
//
// `/snapshots/` e o NOME do snapshotter, nunca `/fs/` sozinho: o último é
// genérico demais para casar dentro de uma árvore que MISTURA binário de host
// com camada, que é exatamente o caso destas raízes — um caminho de host com um
// diretório chamado `fs` no meio voltaria a produzir o falso CRITICAL que esta
// lista existe para evitar. O caminho real do containerd tem os dois:
//
//	…/io.containerd.snapshotter.v1.overlayfs/snapshots/12/fs/usr/sbin/nginx
//
// e o binário de host do k3s (…/k3s/data/<hash>/bin/containerd) não tem nenhum.
var marcasDeCamada = []string{
	"/diff/", "/merged/", "/rootfs/", "/snapshots/", "io.containerd.snapshotter",
}

// EmCamadaDeImagem diz se o caminho está dentro do armazenamento de um runtime
// de contêiner.
func EmCamadaDeImagem(p string) bool {
	for _, r := range raizesDeImagem {
		if strings.HasPrefix(p, r) {
			return true
		}
	}
	for _, r := range raizesMistas {
		if !strings.HasPrefix(p, r) {
			continue
		}
		for _, m := range marcasDeCamada {
			if strings.Contains(p, m) {
				return true
			}
		}
	}
	return false
}

// classificaContainers preenche o campo Contêiner de cada processo, e diz se a
// PRÓPRIA ferramenta está rodando dentro de um.
//
// A segunda pergunta importa: de dentro de um contêiner, todo processo visível
// é do mesmo contêiner, e a distinção "contêiner x host" não significa nada. A
// exclusão da pergunta de propriedade só vale quando estamos no host.
func classificaContainers(f *Facts) {
	f.Host.EmContainer = ferramentaEmContainer(f)
	for i := range f.Processes {
		p := &f.Processes[i]
		if rt, id := ContainerDoCgroup(p.Cgroup); rt != "" {
			p.Container = rt
			p.ContainerID = id
		}
	}
}

// ferramentaEmContainer usa evidência de RUNTIME, não arquivo-marca.
//
// O `/.dockerenv` parece a resposta óbvia e é uma armadilha: ele é um ARQUIVO, e
// arquivo viaja. Provisionar um host a partir de imagem de contêiner —
// `docker export | tar -x` num rootfs — é prática comum, e leva a marca junto.
// A VM desta suíte é construída exatamente assim, e por causa disso a primeira
// versão deste código declarava uma máquina com kernel próprio como contêiner.
// Todo host provisionado dessa forma seria classificado errado.
//
// O que NÃO viaja é o arranjo de montagem:
//
//	raiz em overlay      docker, podman e containerd montam / como overlayfs.
//	                     Um host com rootfs exportado de imagem tem / num
//	                     dispositivo de bloco, e é isso que separa os dois
//	pid 1 em cgroup de   fecha o caso quando o namespace de cgroup NÃO está
//	runtime              isolado; quando está, ele mostra "/" dos dois lados e
//	                     por isso sozinho não serve
//	container= no        escrito pelo RUNTIME ao criar o namespace (nspawn, LXC
//	environ do pid 1     e podman o põem). Não viaja num rootfs exportado, que é
//	                     o teste que o /.dockerenv falha. Exige root para ler;
//	                     sem ele este sinal simplesmente não opina
//
// O TERCEIRO sinal entrou porque os dois primeiros falhavam JUNTOS num caso
// comum: LXC e systemd-nspawn usam rootfs de diretório ou btrfs — não overlay —
// e, com namespace de cgroup (padrão desde LXC 3 e systemd 240), o pid 1 mostra
// "/". A ferramenta se declarava no host, e aí os programas eBPF do host
// apareciam sem dono e o taint do kernel do host virava acusação.
//
// O arquivo-marca continua NÃO sendo lido: ele é a única fonte que viaja com um
// rootfs copiado, e por isso é a única que não decide nada.
//
// O que este arranjo ainda erra: contêiner com storage-driver que não seja
// overlay, namespace de cgroup isolado E environ do pid 1 ilegível (varredura
// sem root) sai como host. A consequência é voltar ao comportamento antigo — os
// binários de imagem entram na pergunta de propriedade —, que é ruído e não
// mentira.
func ferramentaEmContainer(f *Facts) bool {
	for i := range f.Mounts {
		m := &f.Mounts[i]
		if m.Ponto == "/" && ehRaizDeImagem(m.Tipo) {
			return true
		}
	}
	for i := range f.Processes {
		p := &f.Processes[i]
		if p.PID != 1 {
			continue
		}
		if rt, _ := ContainerDoCgroup(p.Cgroup); rt != "" {
			return true
		}
		// TERCEIRO sinal, e ele fecha o buraco que os dois de cima deixavam
		// juntos: LXC e systemd-nspawn usam rootfs de DIRETÓRIO ou btrfs — não
		// overlay — e, com namespace de cgroup (padrão desde LXC 3 e systemd
		// 240), o pid 1 mostra "/" no cgroup. Os dois sinais falhavam ao mesmo
		// tempo e a ferramenta se declarava no host.
		//
		// `container=` no environ do pid 1 é escrito pelo RUNTIME no momento em
		// que ele cria o namespace (systemd-nspawn, LXC e podman o põem), então
		// não viaja num rootfs exportado — que é o teste que o /.dockerenv
		// falha, e a razão de ele não ser lido aqui. Sem root o environ do pid 1
		// é ilegível e este sinal simplesmente não opina; os outros dois valem.
		if p.Env["container"] != "" {
			return true
		}
	}
	return false
}

// ehRaizDeImagem casa as grafias de overlay que aparecem como tipo da raiz.
//
// fuse-overlayfs é o driver do podman ROOTLESS — o `/proc/mounts` escreve
// "fuse.fuse-overlayfs" —, e sem ele toda varredura rootless se declarava no
// host: os programas eBPF do host apareciam sem dono e o taint do kernel do
// host virava acusação, em vez de serem rebaixados por escopo.
func ehRaizDeImagem(tipo string) bool {
	switch tipo {
	case "overlay", "overlayfs", "fuse.fuse-overlayfs", "fuse-overlayfs":
		return true
	}
	return false
}
