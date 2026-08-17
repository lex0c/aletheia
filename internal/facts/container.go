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
	"/var/lib/containerd/", "/run/containerd/io.containerd.runtime",
	"/var/lib/containers/storage/", "/var/lib/rancher/",
	"/var/lib/lxc/", "/var/lib/machines/",
}

// EmCamadaDeImagem diz se o caminho está dentro do armazenamento de um runtime
// de contêiner.
func EmCamadaDeImagem(p string) bool {
	for _, r := range raizesDeImagem {
		if strings.HasPrefix(p, r) {
			return true
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
//
// O arquivo-marca não é lido em lugar nenhum: se ele não decide, e o arranjo de
// montagem já decide, lê-lo só criaria uma segunda fonte para discordar da
// primeira.
//
// O que este arranjo erra: contêiner com storage-driver que não seja overlay
// (devicemapper, btrfs, zfs) E namespace de cgroup isolado sai como host. A
// consequência é voltar ao comportamento antigo — os binários de imagem entram
// na pergunta de propriedade —, que é ruído e não mentira.
func ferramentaEmContainer(f *Facts) bool {
	for i := range f.Mounts {
		m := &f.Mounts[i]
		if m.Ponto == "/" && (m.Tipo == "overlay" || m.Tipo == "overlayfs") {
			return true
		}
	}
	for i := range f.Processes {
		if f.Processes[i].PID == 1 {
			if rt, _ := ContainerDoCgroup(f.Processes[i].Cgroup); rt != "" {
				return true
			}
		}
	}
	return false
}
