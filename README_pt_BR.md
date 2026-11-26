# shadowsocks-libev

[![Build Status](https://travis-ci.com/shadowsocks/shadowsocks-libev.svg?branch=master)](https://travis-ci.com/shadowsocks/shadowsocks-libev) [![Snap Status](https://build.snapcraft.io/badge/shadowsocks/shadowsocks-libev.svg)](https://build.snapcraft.io/user/shadowsocks/shadowsocks-libev)

## Introdução

[Shadowsocks-libev](https://shadowsocks.org) é um SOCKS5 leve e seguro
proxy para dispositivos embutidos e caixas de baixo custo.

É uma porta de [Shadowsocks](https://github.com/shadowsocks/shadowsocks)
criado por [@clowwindy](https://github.com/clowwindy) e mantido por
[@madeye](https://github.com/madeye) e [@linusyang](https://github.com/linusyang).

Versão atual: 3.3.6 | [Changelog](debian/changelog)

## Características

Shadowsocks-libev é escrito em C puro e depende de [libev](http://software.schmorp.de/pkg/libev.html). Ele foi projetado para ser uma implementação leve do protocolo shadowsocks, a fim de manter o uso de recursos o mais baixo possível.

Para obter uma lista completa de comparação de recursos entre diferentes versões de shadowsocks, consulte a [página da Wiki (https://github.com/shadowsocks/shadowsocks/wiki/Feature-Comparison-across-Different-Versions).

## Começo rápido

Snap é a maneira recomendada de instalar os binários mais recentes.

### Instale o snap core

https://snapcraft.io/core

### Instalar a partir do snapcraft.io

Stable channel:

```bash
sudo snap install shadowsocks-libev
```

Edge channel:

```bash
sudo snap install shadowsocks-libev --edge
```

## Instalação

### Guia específico de distribuição

- [Debian & Ubuntu](#debian--ubuntu)
    + [Instalar do repositório](#instale-a-partir-do-repositório-não-recomendado)
    + [Construa o pacote deb a partir da fonte](#compile-o-pacote-deb-a-partir-da-fonte)
    + [Configurar e iniciar o serviço](#configurar-e-iniciar-o-serviço)
- [Fedora & RHEL](#fedora--rhel)
     + [Construir a partir da fonte com centos](#construa-a-partir-da-fonte-com-centos)
- [Archlinux & Manjaro](#archlinux--manjaro)
- [NixOS](#nixos)
- [Nix](#nix)
- [Compile e instale diretamente no sistema semelhante ao UNIX](#linux)
- [FreeBSD](#freebsd)
     + [Instalar](#instalar)
     + [Configuração](#configuração)
     + [Executar](#executar)
     + [Executar como cliente](#executar-como-cliente)
- [OpenWRT](#openwrt)
- [OS X](#os-x)
- [Windows (MinGW)](#windows-mingw)

* * *

### Inicialize o ambiente de compilação

Este repositório usa submódulos, então você deve puxá-los antes de começar, usando:

```bash
git submodule update --init --recursive
```

### Guia de configuração de pré-compilação

Para obter uma lista completa das opções de tempo de configuração disponíveis,
tentar `configure --help`.

### Debian & Ubuntu

#### Instale a partir do repositório (não recomendado)

Shadowsocks-libev está disponível no repositório oficial para as seguintes distribuições:

* Debian 8 ou superior, incluindo oldoldstable (jessie), old stable (stretch), stable (buster), testing (bullseye) e unstable (sid)
* Ubuntu 16.10 ou superior

```bash
sudo apt update
sudo apt install shadowsocks-libev
```

#### Compile o pacote deb a partir da fonte.

Distribuições suportadas:

* Debian 8, 9 ou superior
* Ubuntu 14.04 LTS, 16.04 LTS, 16.10 ou superior

Você pode construir shadowsocks-libev e todas as suas dependências por script:

```bash
mkdir -p ~/build-area/
cp ./scripts/build_deb.sh ~/build-area/
cd ~/build-area
./build_deb.sh
```

Para sistemas mais antigos, a construção de pacotes `.deb` não é suportada.
Por favor, tente construir e instalar diretamente da fonte. Veja a seção [Linux](#linux) abaixo.

**Nota para usuários do Debian 8 (Jessie) para construir seus próprios pacotes deb**:

Nós encorajamos você a instalar shadowsocks-libev de `jessie-backports-sloppy`. Se você insistir em compilar a partir da fonte, você precisará instalar manualmente o libsodium de `jessie-backports-sloppy`, **NÃO** libsodium no repositório principal.

Para mais informações sobre backports, você pode consultar [Debian Backports](https://backports.debian.org).

``` bash
cd shadowsocks-libev
sudo sh -c 'printf "deb http://deb.debian.org/debian jessie-backports main" > /etc/apt/sources.list.d/jessie-backports.list'
sudo sh -c 'printf "deb http://deb.debian.org/debian jessie-backports-sloppy main" >> /etc/apt/sources.list.d/jessie-backports.list'
sudo apt-get install --no-install-recommends devscripts equivs
mk-build-deps --root-cmd sudo --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"
./autogen.sh && dpkg-buildpackage -b -us -uc
cd ..
sudo dpkg -i shadowsocks-libev*.deb
```

**Nota para usuários do Debian 9 (Stretch) para construir seus próprios pacotes deb**:

Nós encorajamos você a instalar shadowsocks-libev de `stretch-backports`. Se você insistir em compilar a partir do código-fonte, precisará instalar manualmente o libsodium de `stretch-backports`, **NÃO** libsodium no repositório principal.

Para mais informações sobre backports, você pode consultar [Debian Backports](https://backports.debian.org).

``` bash
cd shadowsocks-libev
sudo sh -c 'printf "deb http://deb.debian.org/debian stretch-backports main" > /etc/apt/sources.list.d/stretch-backports.list'
sudo apt-get install --no-install-recommends devscripts equivs
mk-build-deps --root-cmd sudo --install --tool "apt-get -o Debug::pkgProblemResolver=yes --no-install-recommends -y"
./autogen.sh && dpkg-buildpackage -b -us -uc
cd ..
sudo dpkg -i shadowsocks-libev*.deb
```

#### Configurar e iniciar o serviço

```
# Edite o arquivo de configuração
sudo vim /etc/shadowsocks-libev/config.json

# Edite a configuração padrão do debian
sudo vim /etc/default/shadowsocks-libev

# Inicia o serviço
sudo /etc/init.d/shadowsocks-libev start    # para sysvinit, ou
sudo systemctl start shadowsocks-libev      # para systemd
```

### Fedora & RHEL

Distribuições suportadas:

* Versões recentes do Fedora (até EOL)
* RHEL 6, 7 e derivados (incluindo CentOS, Scientific Linux)

#### Construa a partir da fonte com centos

Se você estiver usando o CentOS 7, precisará instalar estes pré-requisitos para compilar a partir do código-fonte:

```bash
yum install epel-release -y
yum install gcc gettext autoconf libtool automake make pcre-devel doxygen c-ares-devel libev-devel libsodium-devel mbedtls-devel -y
```

### Archlinux & Manjaro

```bash
sudo pacman -S shadowsocks-libev
```

Consulte o script downstream [PKGBUILD](https://github.com/archlinux/svntogit-community/blob/packages/shadowsocks-libev/trunk/PKGBUILD) para modificações extras e bugs específicos da distribuição.

### NixOS

```bash
nix-env -iA nixos.shadowsocks-libev
```

### Nix

```bash
nix-env -iA nixpkgs.shadowsocks-libev
```

### Linux

Em geral, você precisa das seguintes dependências de compilação:

* autotools (autoconf, automake, libtool)
* gettext
* pkg-config
* libmbedtls
* libsodium
* libpcre3 (antiga biblioteca pcre)
* libev
* libc-ares
* Doxygen 1.9.4+ (somente para documentação)

Notas: Fedora 26 libsodium versão >= 1.0.12, então você pode instalar via dnf install libsodium em vez de compilar a partir da fonte.

Se seu sistema for muito antigo para fornecer libmbedtls e libsodium (posterior a **v1.0.8**), você precisará instalar essas bibliotecas manualmente ou atualizar seu sistema.

Se o seu sistema fornece essas bibliotecas, você **não deve** instalá-las a partir do código-fonte. Você deve ir para esta seção e instalá-las a partir do repositório de distribuição.

Para algumas das distribuições, você pode instalar dependências de compilação como esta:

```bash
# Instalação de dependências básicas de compilação
## Debian / Ubuntu
sudo apt-get install --no-install-recommends gettext build-essential autoconf libtool libpcre3-dev doxygen libev-dev libc-ares-dev automake libmbedtls-dev libsodium-dev pkg-config
## CentOS / Fedora / RHEL
sudo yum install gettext gcc autoconf libtool automake make doxygen c-ares-devel libev-devel
## Arch
sudo pacman -S gettext gcc autoconf libtool automake make doxygen c-ares libev

# Instalação do libsodium
export LIBSODIUM_VER=1.0.16
wget https://download.libsodium.org/libsodium/releases/old/libsodium-$LIBSODIUM_VER.tar.gz
tar xvf libsodium-$LIBSODIUM_VER.tar.gz
pushd libsodium-$LIBSODIUM_VER
./configure --prefix=/usr && make
sudo make install
popd
sudo ldconfig

# Instalação do MbedTLS
export MBEDTLS_VER=2.6.0
wget https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/mbedtls-$MBEDTLS_VER.tar.gz
tar xvf mbedtls-$MBEDTLS_VER.tar.gz
pushd mbedtls-$MBEDTLS_VER
make SHARED=1 CFLAGS="-O2 -fPIC"
sudo make DESTDIR=/usr install
popd
sudo ldconfig

# Comece a construir
./autogen.sh && ./configure && make
sudo make install
```

Pode ser necessário instalar manualmente os softwares ausentes.

### FreeBSD
#### Instalar
Shadowsocks-libev está disponível na Coleção de Ports do FreeBSD. Você pode instalá-lo de qualquer maneira, `pkg` ou `ports`.

**pkg (recomendado)**

```bash
pkg install shadowsocks-libev
```

**portas**

```bash
cd /usr/ports/net/shadowsocks-libev
make install
```

#### Configuração
Edite seu arquivo `config.json`. Por padrão, está localizado em `/usr/local/etc/shadowsocks-libev`.

Para habilitar shadowsocks-libev, adicione a seguinte variável rc ao seu arquivo `/etc/rc.conf`:

```
shadowsocks_libev_enable="YES"
```

#### Executar

Inicie o servidor Shadowsocks:

```bash
service shadowsocks_libev start
```

#### Executar como cliente
Por padrão, shadowsocks-libev está rodando como um servidor no FreeBSD. Se você quiser iniciar o shadowsocks-libev no modo cliente, você pode modificar o script rc (`/usr/local/etc/rc.d/shadowsocks_libev`) manualmente.

```
# modifique a seguinte linha de "ss-server" para "ss-local"
command="/usr/local/bin/ss-local"
```

Observe que é simplesmente uma solução alternativa, cada vez que você atualizar a porta, suas alterações serão substituídas pela nova versão.

### OpenWRT

O projeto OpenWRT é mantido aqui:
[openwrt-shadowsocks](https://github.com/shadowsocks/openwrt-shadowsocks).

### OS X
Para OS X, use [Homebrew](http://brew.sh) para instalar ou compilar.

Instale o Homebrew:

```bash
ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"
```
Instale shadowsocks-libev:

```bash
brew install shadowsocks-libev
```

### Windows (MinGW)

O build atual usa CMake. Consulte o README em inglês para as instruções de
compilação nativa e cruzada. Os scripts antigos de Docker/MinGW foram removidos.

## Utilização

Para obter uma lista detalhada e completa de todos os argumentos suportados,
você pode consultar as páginas de manual dos aplicativos, respectivamente.

     ss-[local|server|tunnel|manager]

       -s <server_host>            Nome do host ou endereço IP de seu servidor remoto.

       -p <server_port>            Número da porta do seu servidor remoto.

       -l <local_port>             Número da porta do seu servidor local.

       -k <password>               Senha do seu servidor remoto.

       -m <encrypt_method>         Método de criptografia:
                                   aes-128-gcm, aes-192-gcm, aes-256-gcm,
                                   chacha20-ietf-poly1305 e
                                   xchacha20-ietf-poly1305.
                                   A cifra padrão é chacha20-ietf-poly1305.

       [-a <user>]                 Executar como outro usuário.

       [-f <pid_file>]             O caminho do arquivo para armazenar pid.

       [-t <timeout>]              Tempo limite do soquete em segundos.

       [-c <config_file>]          O caminho para o arquivo de configuração.

       [-n <number>]               Número máximo de arquivos abertos.

       [-i <interface>]            Interface de rede a ser vinculada.

       [-b <local_address>]        Endereço local para ligar.
                                   Para servidores: Especifique o endereço local a ser usado
                                   enquanto este servidor está fazendo saída
                                   conexões a servidores remotos em nome do
                                   clientes.
                                   Para clientes: Especifique o endereço local a ser usado
                                   enquanto este cliente está fazendo saída
                                   conexões com o servidor.

       [-u]                        Habilita retransmissão UDP.

       [-U]                        Ativa a retransmissão UDP e desativa a retransmissão TCP.
                                   (não disponível no modo local)

       [-L <addr>:<port>]          Endereço e porta do servidor de destino
                                   para encaminhamento de porta local.
                                   (disponível apenas no modo túnel)

       [-6]                        Primeiro, resolva o nome do host para o endereço IPv6.

       [-d <addr>]                 Servidores de nome para resolvedor de DNS interno.
                                   (disponível apenas no modo servidor)

       [--reuse-port]              Habilita a reutilização de porta.

       [--fast-open]               Habilita a abertura rápida do TCP.
                                   com kernel do Linux > 3.7.0.
                                   (disponível apenas no modo local e servidor)

       [--acl <acl_file>]          Caminho para ACL (lista de controle de acesso).
                                   (disponível apenas no modo local e servidor)

       [--manager-address <addr>]  endereço de soquete do domínio UNIX.
                                   (disponível apenas no modo servidor e gerenciador)

       [--mtu <MTU>]               MTU de sua interface de rede.

       [--mptcp]                   Habilita o Multipath TCP no Kernel MPTCP.
 
       [--no-delay]                Habilita TCP_NODELAY.

       [--executable <path>]       Caminho para o executável do ss-server.
                                   (disponível apenas no modo gerenciador)
 
       [-D <path>]                 Caminho para o diretório de trabalho do ss-manager.
                                   (disponível apenas no modo gerenciador)

       [--key <key_in_base64>]     Chave do seu servidor remoto.

## Dicas de segurança

Para qualquer servidor público, para evitar que os usuários acessem o localhost do seu servidor, adicione `--acl acl/server_block_local.acl` à linha de comando.

Embora shadowsocks-libev possa lidar bem com milhares de conexões simultâneas, ainda recomendamos
configurando as regras de firewall do seu servidor para limitar as conexões de cada usuário:

    # Até 32 conexões são suficientes para uso normal
    iptables -A INPUT -p tcp --syn --dport ${SHADOWSOCKS_PORT} -m connlimit --connlimit-above 32 -j REJECT --reject-with tcp-reset

## Licença

```
Copyright: 2013-2015, Clow Windy <clowwindy42@gmail.com>
           2013-2018, Max Lv <max.c.lv@gmail.com>
           2014, Linus Yang <linusyang@gmail.com>

Este programa é um software livre: você pode redistribuí-lo 
e/ou modificá-lo sob os termos da GNU General Public License 
conforme publicada pela Free Software Foundation, a versão 3
da Licença ou (a seu critério) qualquer versão posterior.

Este programa é distribuído na esperança de que seja útil,
 mas SEM QUALQUER GARANTIA; sem mesmo a garantia implícita 
de COMERCIALIZAÇÃO ou ADEQUAÇÃO A UM DETERMINADO FIM.Veja
a Licença Pública Geral GNU para mais detalhes.

Você deve ter recebido uma cópia da GNU General Public License 
juntamente com este programa. Caso contrário, 
consulte <http://www.gnu.org/licenses/>.
```
