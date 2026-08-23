
# Guía Técnica: Instalación de Agente Wazuh en Alpine

**Universidad de los Andes - Colombia**  
Ingeniería de Sistemas y Computación | Ciberseguridad


---

# Solución 

## Paso 1 — Paquetes de desarrollo en Alpine

```bash
apk update && apk add --no-cache \
  build-base cmake git curl unzip tar automake autoconf libtool pkgconfig \
  linux-headers musl-dev bsd-compat-headers gettext-dev \
  clang llvm zlib-dev elfutils-dev
```

`clang`, `llvm`, `zlib-dev` y `elfutils-dev` son necesarios porque el agente
4.12 incluye monitoreo con eBPF (módulo FIM/whodata), que requiere compilar
programas BPF con Clang y enlazar contra `libbpf`.

---

## Paso 2 — Clonar Wazuh 4.12.0 y crear cabeceras de compatibilidad musl/BPF

```bash
rm -rf /root/wazuh
git clone --depth 1 --branch v4.12.0 https://github.com/wazuh/wazuh.git /root/wazuh

mkdir -p /usr/include/linux /usr/include/bpf

cat << 'EOF' > /usr/include/linux/compiler.h
#ifndef _LINUX_COMPILER_H
#define _LINUX_COMPILER_H
#include <linux/bpf.h>
#ifndef __user
#define __user
#endif
#ifndef __force
#define __force
#endif
#ifndef __must_check
#define __must_check
#endif
#ifndef __always_inline
#define __always_inline inline
#endif
#ifndef __noreturn
#define __noreturn __attribute__((noreturn))
#endif
#ifndef __weak
#define __weak __attribute__((weak))
#endif
#ifndef __packed
#define __packed __attribute__((packed))
#endif
#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif
#ifndef __printf
#define __printf(a, b) __attribute__((format(printf, a, b)))
#endif
#ifndef __maybe_unused
#define __maybe_unused __attribute__((unused))
#endif
#ifndef __always_unused
#define __always_unused __attribute__((unused))
#endif
#ifndef fallthrough
#define fallthrough __attribute__((fallthrough))
#endif
#ifndef BPF_REG_0
#define BPF_REG_0 0
#endif
#ifndef BPF_MOV64_IMM
#define BPF_MOV64_IMM(DST, IMM) \
  ((struct bpf_insn) { \
    .code  = 0xb7, \
    .dst_reg = DST, \
    .src_reg = 0, \
    .off   = 0, \
    .imm   = IMM })
#endif
#ifndef BPF_EXIT_INSN
#define BPF_EXIT_INSN() \
  ((struct bpf_insn) { \
    .code  = 0x95, \
    .dst_reg = 0, \
    .src_reg = 0, \
    .off   = 0, \
    .imm   = 0 })
#endif
#endif
EOF

cat << 'EOF' > /usr/include/linux/kernel.h
#ifndef _LINUX_KERNEL_H
#define _LINUX_KERNEL_H
#include <sys/param.h>
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif
#ifndef roundup
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#endif
#endif
EOF

cat << 'EOF' > /usr/include/linux/err.h
#ifndef _LINUX_ERR_H
#define _LINUX_ERR_H
#include <linux/compiler.h>
#include <errno.h>
#include <stdbool.h>
#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) ((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)
static inline void *ERR_PTR(long error) { return (void *) error; }
static inline long PTR_ERR(const void *ptr) { return (long) ptr; }
static inline bool IS_ERR(const void *ptr) { return IS_ERR_VALUE((unsigned long)ptr); }
static inline bool IS_ERR_OR_NULL(const void *ptr) { return !ptr || IS_ERR_VALUE((unsigned long)ptr); }
static inline void *ERR_CAST(const void *ptr) { return (void *) ptr; }
static inline int PTR_ERR_OR_ZERO(const void *ptr) { return IS_ERR(ptr) ? PTR_ERR(ptr) : 0; }
#endif
EOF

cat << 'EOF' > /usr/include/linux/bpf_insn.h
#ifndef _LINUX_BPF_INSN_H
#define _LINUX_BPF_INSN_H
#include <linux/bpf.h>
#ifndef BPF_REG_0
#define BPF_REG_0 0
#endif
#ifndef BPF_MOV64_IMM
#define BPF_MOV64_IMM(DST, IMM) \
  ((struct bpf_insn) { \
    .code  = 0xb7, \
    .dst_reg = DST, \
    .src_reg = 0, \
    .off   = 0, \
    .imm   = IMM })
#endif
#ifndef BPF_EXIT_INSN
#define BPF_EXIT_INSN() \
  ((struct bpf_insn) { \
    .code  = 0x95, \
    .dst_reg = 0, \
    .src_reg = 0, \
    .off   = 0, \
    .imm   = 0 })
#endif
#endif
EOF
cp /usr/include/linux/bpf_insn.h /usr/include/bpf/bpf_insn.h

if ! grep -q "BPF_MAP_TYPE_ARENA" /usr/include/linux/bpf.h 2>/dev/null; then
cat << 'EOF' >> /usr/include/linux/bpf.h
#ifndef BPF_MAP_TYPE_ARENA
#define BPF_MAP_TYPE_ARENA 31
#endif
EOF
fi
```

Para lograr compilar con éxito el agente de **Wazuh 4.12.0** en **Alpine Linux**, es necesario crear cabeceras de compatibilidad personalizadas. 
Alpine utiliza **musl libc** en lugar de **glibc** y cuenta con un conjunto reducido de cabeceras del espacio de usuario (*userspace*) del kernel de Linux. 
A continuación se detalla el propósito técnico de cada una de las cabeceras e inyecciones de código implementadas:
---

### 1. `/usr/include/linux/compiler.h`
**Propósito:** Proveer macros de atributos del compilador GCC/Clang y definiciones eBPF base.  
**Explicación:** El código de Wazuh (especialmente los módulos de eBPF) utiliza anotaciones específicas del kernel de Linux como `__user`, `__packed`, `__always_inline` o `fallthrough`. En sistemas GNU tradicionales estas provienen de las cabeceras internas del kernel, pero en musl no están presentes por defecto. Esta cabecera evita errores de sintaxis definiendo estos atributos para el compilador.


### 2. `/usr/include/linux/kernel.h`
**Propósito:** Ofrecer macros utilitarias estándar para manipulación de datos y memoria.  
**Explicación:** Define utilidades fundamentales a nivel de sistema que el código de Wazuh espera encontrar en las cabeceras del kernel, tales como `ARRAY_SIZE` (utilizada para calcular de manera segura la cantidad de elementos en un arreglo) y `roundup` (empleada en el alinhamiento de bloques de memoria).


### 3. `/usr/include/linux/err.h`
**Propósito:** Recrear la API de gestión de errores basada en punteros del kernel de Linux.  
**Explicación:** En el desarrollo de Linux es habitual codificar valores de error (`errno`) directamente dentro de direcciones de puntero devueltas por funciones. Funciones inline como `IS_ERR()`, `PTR_ERR()` y `ERR_PTR()` permiten a Wazuh inspeccionar y manipular estos punteros de error sin depender de las librerías del kernel en espacio de usuario.


### 4. `/usr/include/linux/bpf_insn.h` y `/usr/include/bpf/bpf_insn.h`
**Propósito:** Proporcionar las estructuras e instrucciones base del ensamblador eBPF.  
**Explicación:** Suministra las definiciones de registros e instrucciones esenciales de eBPF (como `BPF_MOV64_IMM` y `BPF_EXIT_INSN`). Al duplicar este archivo en ambas rutas (`/linux/` y `/bpf/`), se garantiza la compatibilidad tanto si el código fuente de Wazuh incluye el archivo mediante `<linux/bpf_insn.h>` como si lo hace mediante `<bpf/bpf_insn.h>`.

### 5. Parche a `/usr/include/linux/bpf.h` (`BPF_MAP_TYPE_ARENA`)
**Propósito:** Garantizar la definición del tipo de mapa eBPF `BPF_MAP_TYPE_ARENA`.  
**Explicación:** `BPF_MAP_TYPE_ARENA` es una constante agregada en versiones recientes del kernel Linux para asignación de memoria compartida en eBPF. Si la versión de las cabeceras del kernel instaladas en Alpine es anterior o no la incluye, esta inyección asegura que el código de Wazuh encuentre la constante (con valor `31`) y compile sin arrojar errores de símbolo no declarado.

---

## Paso 3 — Dependencias externas oficiales (reemplaza submódulos git, que no funcionan aquí)

```bash
cd /root/wazuh/src
make deps TARGET=agent EXTERNAL_SRC_ONLY=yes
```

`EXTERNAL_SRC_ONLY=yes` pide código fuente (para compilarlo contra musl) en
vez de binarios precompilados (que asumen glibc).

### 3.1 — Excepción: `libbpf-bootstrap` necesita el paquete PRECOMPILADO

El programa eBPF del módulo FIM/whodata (`modern.bpf.c`) usa builtins CO-RE de
Clang (`__builtin_preserve_access_index`) que Wazuh compila en un pipeline de
CI dedicado por arquitectura — no está pensado para compilarse en cualquier
máquina. Si se deja como fuente, falla con errores de `implicit declaration`
o `assignment... makes pointer from integer`. La solución es descartar la
versión fuente y dejar que `make deps` traiga la versión precompilada
(bytecode BPF, que no depende de glibc/musl):

```bash
rm -rf /root/wazuh/src/external/libbpf-bootstrap
cd /root/wazuh/src
make deps TARGET=agent
```

(sin `EXTERNAL_SRC_ONLY=yes` esta vez — como todo lo demás en `src/external`
ya existe, `make deps` solo repuebla la carpeta que borramos, y esta vez con
el binario ya compilado por Wazuh).

---

## Paso 4 — Parche de OpenSSL para musl (bug de `strerror_r`)

**El problema:** `crypto/o_str.c` de OpenSSL decide qué variante de
`strerror_r` usar según `#elif defined(_GNU_SOURCE)`. En glibc, definir
`_GNU_SOURCE` cambia `strerror_r` para que devuelva `char *`. **musl nunca
implementa esa variante** — su `strerror_r` siempre devuelve `int`, sin
importar qué macros de feature test estén definidas. Como compilamos con
`-D_GNU_SOURCE` globalmente, OpenSSL entra por la rama equivocada y falla:

```
error: assignment to 'char *' from 'int' makes pointer from integer without a cast
```

**La corrección** — parchar la condición para que en musl (donde `__GLIBC__`
nunca está definido) caiga en la rama correcta (la que sí funciona con `int`,
que musl activa automáticamente vía `_POSIX_C_SOURCE`):

```bash
sed -i 's/#elif defined(_GNU_SOURCE)/#elif defined(_GNU_SOURCE) \&\& defined(__GLIBC__)/' \
  /root/wazuh/src/external/openssl/crypto/o_str.c
```

---

## Paso 5 — Compatibilidad de símbolos glibc faltantes en musl

Wazuh (concretamente `sysinfo`/`data_provider` y `libwazuhext`) llama a
varias funciones que son extensiones exclusivas de glibc y que **musl nunca
implementa**: la familia `_r` reentrante (`random_r`), los alias de
dispositivo `gnu_dev_*`, toda la familia LFS64 (`open64`, `stat64`,
`mkstemp64`, etc.), alias internos (`__strtok_r`, `__strdup`,
`__rawmemchr`), `glob_pattern_p`, y el contexto de ejecución
(`getcontext`/`setcontext`/`makecontext`, que musl omite a propósito por
decisión de diseño, ya retirado de POSIX).

### 5.1 — Compilar `libexecinfo` (para `backtrace`/`backtrace_symbols`)

Alpine eliminó el paquete `libexecinfo-dev` de sus repositorios a partir de
la versión 3.17 — hay que compilarlo desde el fork mantenido para musl:

```bash
git clone https://github.com/ronchaine/libexecinfo.git /root/libexecinfo
cd /root/libexecinfo
make
cp execinfo.h /usr/include/
cp libexecinfo.a /usr/lib/
cp libexecinfo.so.1 /usr/lib/
ln -sf /usr/lib/libexecinfo.so.1 /usr/lib/libexecinfo.so
```

### 5.2 — Compilar `libucontext` (para `getcontext`/`setcontext`/`makecontext`)

```bash
git clone https://github.com/kaniini/libucontext.git /root/libucontext
cd /root/libucontext
make ARCH=x86_64
make ARCH=x86_64 DESTDIR=/usr install
```

> **Ojo:** el `Makefile` de `libucontext` ya trae `/usr` como prefijo interno
> fijo. Si con `DESTDIR=/usr` los archivos terminan en `/usr/usr/lib/` y
> `/usr/usr/include/` en vez de `/usr/lib/`/`/usr/include/`, muévanlos a mano:
> ```bash
> cp -a /usr/usr/lib/. /usr/lib/
> cp -a /usr/usr/include/. /usr/include/
> rm -rf /usr/usr
> ```

`libucontext` exporta sus símbolos con el prefijo `libucontext_*`
(`libucontext_getcontext`, etc.) más alias débiles (`weak`) sin prefijo. En
la práctica, esos alias débiles no siempre se resuelven de forma confiable
cuando quedan enterrados dentro de un enlace `--whole-archive`, así que el
shim del siguiente paso los redirige explícitamente.

### 5.3 — El shim de compatibilidad completo (`musl_compat.c`)

Esta es la versión final, que ya incluye las redirecciones explícitas hacia
`libucontext` (evita depender de sus símbolos débiles):

```bash
mkdir -p /root/wazuh/src/external/musl_compat
cat << 'EOF' > /root/wazuh/src/external/musl_compat/musl_compat.c
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/sysmacros.h>
#include <unistd.h>

struct random_data { unsigned int seed; };
int srandom_r(unsigned int seed, struct random_data *buf) {
    if (!buf) return -1;
    buf->seed = seed ? seed : 1;
    return 0;
}
int random_r(struct random_data *buf, int32_t *result) {
    if (!buf || !result) return -1;
    *result = (int32_t) rand_r(&buf->seed);
    return 0;
}
int initstate_r(unsigned int seed, char *statebuf, size_t statelen, struct random_data *buf) {
    (void) statebuf; (void) statelen;
    return srandom_r(seed, buf);
}
unsigned int gnu_dev_major(unsigned long long dev) { return major(dev); }
unsigned int gnu_dev_minor(unsigned long long dev) { return minor(dev); }
unsigned long long gnu_dev_makedev(unsigned int maj, unsigned int min) { return makedev(maj, min); }
int open64(const char *path, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list ap; va_start(ap, flags);
        mode = (mode_t) va_arg(ap, int);
        va_end(ap);
    }
    return open(path, flags, mode);
}
int mkstemp64(char *tmpl) { return mkstemp(tmpl); }
int ftruncate64(int fd, off_t length) { return ftruncate(fd, length); }
int stat64(const char *path, struct stat *buf) { return stat(path, buf); }
int fstat64(int fd, struct stat *buf) { return fstat(fd, buf); }
int lstat64(const char *path, struct stat *buf) { return lstat(path, buf); }
off_t lseek64(int fd, off_t offset, int whence) { return lseek(fd, offset, whence); }
ssize_t pread64(int fd, void *buf, size_t count, off_t offset) { return pread(fd, buf, count, offset); }
ssize_t pwrite64(int fd, const void *buf, size_t count, off_t offset) { return pwrite(fd, buf, count, offset); }
void *mmap64(void *addr, size_t length, int prot, int flags, int fd, off_t offset) { return mmap(addr, length, prot, flags, fd, offset); }
int fseeko64(FILE *stream, off_t offset, int whence) { return fseeko(stream, offset, whence); }
off_t ftello64(FILE *stream) { return ftello(stream); }
FILE *fopen64(const char *path, const char *mode) { return fopen(path, mode); }
FILE *freopen64(const char *path, const char *mode, FILE *stream) { return freopen(path, mode, stream); }
FILE *tmpfile64(void) { return tmpfile(); }
char *__strtok_r(char *str, const char *delim, char **saveptr) { return strtok_r(str, delim, saveptr); }
char *__strdup(const char *s) { return strdup(s); }
void *__rawmemchr(const void *s, int c) { return memchr(s, c, (size_t)-1); }
int glob_pattern_p(const char *pattern, int quote) {
    for (const char *p = pattern; *p; p++) {
        if (*p == '\\' && quote) { if (*(p+1)) p++; continue; }
        if (*p == '*' || *p == '?' || *p == '[') return 1;
    }
    return 0;
}

/* Redirecciones explícitas para libucontext (no depender de sus alias weak) */
int libucontext_getcontext(void *ucp);
int libucontext_setcontext(const void *ucp);
int libucontext_swapcontext(void *oucp, const void *ucp);

__attribute__((visibility("default")))
int getcontext(void *ucp) {
    return libucontext_getcontext(ucp);
}
__attribute__((visibility("default")))
int setcontext(const void *ucp) {
    return libucontext_setcontext(ucp);
}
__attribute__((visibility("default")))
int swapcontext(void *oucp, const void *ucp) {
    return libucontext_swapcontext(oucp, ucp);
}
__asm__(
    ".text\n"
    ".global makecontext\n"
    ".type makecontext, @function\n"
    "makecontext:\n"
    "  jmp libucontext_makecontext\n"
);
EOF

gcc -c -fPIC /root/wazuh/src/external/musl_compat/musl_compat.c \
  -o /root/wazuh/src/external/musl_compat/musl_compat.o
```

---

## Paso 6 — Inyectar el shim en el Makefile de Wazuh

**Por qué no basta con `LDFLAGS`:** la receta de enlace de `libwazuhext.so`
en el `Makefile` de Wazuh está escrita a mano (no es una regla implícita de
Make) y no referencia `$(LDFLAGS)` en ningún lado — exportar la variable de
entorno no tiene ningún efecto sobre ese enlace puntual. La receta real usa
`${OSSEC_LIBS}` directamente (verificado con `grep -n -A20
"^\$(WAZUHEXT_LIB)"` sobre el Makefile), así que esa es la única variable
por la que hay que inyectar nuestras librerías. **`WAZUHEXT_OBJS` no existe
en ninguna receta del Makefile** — si se inyecta ahí, el objeto queda
completamente ignorado y solo se resuelven los símbolos que ya traían
`libucontext.a`/`libexecinfo.a` por su cuenta (`getcontext`, `backtrace`,
etc.), mientras que los símbolos propios de `musl_compat.c` (`gnu_dev_*`,
`__strtok_r`, `glob_pattern_p`, la familia `*64`) siguen indefinidos.

```bash
cd /root/wazuh/src

# 1. Restaurar el Makefile a su estado original (por si quedó algún sed
#    manual o una inyección previa en la variable equivocada)
git checkout Makefile

# 2. Inyectar el objeto de compatibilidad y las librerías necesarias
#    TODO en OSSEC_LIBS — es la variable que la receta real usa
cat << 'EOF' >> Makefile
# Inyección de compatibilidad musl
OSSEC_LIBS += /root/wazuh/src/external/musl_compat/musl_compat.o /usr/lib/libucontext.a /usr/lib/libexecinfo.a
EOF
```

### Reconstruir `libwazuhext.so` y verificar

```bash
rm -f libwazuhext.so
make TARGET=agent CFLAGS="-D_GNU_SOURCE -I/usr/include -include /usr/include/linux/bpf_insn.h -Wno-error=incompatible-pointer-types" libwazuhext.so

# Deben aparecer como 'T' (definido), no 'U' (indefinido)
nm -D libwazuhext.so | grep -E 'getcontext|setcontext|makecontext'
```

---

## Paso 7 — Compilación completa del agente (con `CMAKE_OPTS` para los sub-builds de CMake)

`sysinfo`/`data_provider` y `syscollector` son sub-proyectos de **CMake**
anidados dentro del Makefile principal — CMake no lee `LDFLAGS` del entorno,
así que sus flags de enlace hay que pasarlos por `CMAKE_OPTS`
(`CMAKE_EXE_LINKER_FLAGS` / `CMAKE_SHARED_LINKER_FLAGS`), envolviendo las
librerías estáticas en `--whole-archive`/`--no-whole-archive` para forzar que
se incluyan todos sus símbolos:

```bash
cd /root/wazuh/src
make TARGET=agent \
  CFLAGS="-D_GNU_SOURCE -I/usr/include -include /usr/include/linux/bpf_insn.h -Wno-error=incompatible-pointer-types" \
  CMAKE_OPTS='-DCMAKE_EXE_LINKER_FLAGS="/root/wazuh/src/external/musl_compat/musl_compat.o -Wl,--whole-archive /usr/lib/libexecinfo.a /usr/lib/libucontext.a -Wl,--no-whole-archive" -DCMAKE_SHARED_LINKER_FLAGS="/root/wazuh/src/external/musl_compat/musl_compat.o -Wl,--whole-archive /usr/lib/libexecinfo.a /usr/lib/libucontext.a -Wl,--no-whole-archive"'
```

---

Después de ejecutar este paso y esperar algunos minutos a la compilación del agente, se debería obtener el siguiente resultado:

<img width="947" height="360" alt="image" src="https://github.com/user-attachments/assets/ff9e0278-abe0-49e8-8097-663f6ce09f9c" />

Una vez en este punto, siempre que se quiera volver a compilar el agente se reducirá el tiempo de espera debido a que...

---

## Paso 8 — Instalar el agente compilado

```bash
cd /root/wazuh
./install.sh
```

Es un script interactivo: elijan **agent** (no manager) cuando pregunte el
tipo de instalación, y acepten el directorio destino por defecto
(`/var/ossec`). Como todo ya se compiló en `src/`, este paso solo copia los
binarios a su ubicación final — no vuelve a compilar nada.

---

## Paso 9 — Registrar el agente

Registrar el agente contra el manager (genera `client.keys`):

```bash
/var/ossec/bin/agent-auth -m IP_DEL_MANAGER
```

> El puerto de **enrollment** (registro, este paso) es el **1515**; el
> puerto de **conexión persistente** (Paso 11, una vez arrancado el agente)
> es el **1514**. Son dos puertos distintos — que uno responda no garantiza
> que el otro también esté abierto en el firewall. Si `agent-auth` falla
> con `Unable to connect to enrollment service`, antes de sospechar de la
> IP, prueben conectividad directa al puerto:
> ```bash
> apk add --no-cache netcat-openbsd
> nc -zv IP_DEL_MANAGER 1515
> ```
> Un timeout apunta a firewall/red (en labs con pfSense segmentado por
> zonas, revisar las reglas entre la zona de este contenedor y la del
> manager); un "connection refused" apunta a que `wazuh-authd` no está
> habilitado/corriendo en el manager.

---

## Paso 10 — Arrancar el agente (parche de `wazuh-control` para BusyBox)

**El problema:** `wazuh-control` verifica si un proceso sigue vivo con
`ps -p $PID`. BusyBox (el `ps` de Alpine) no soporta ese flag de la misma
forma que el `ps` de GNU/coreutils, así que el chequeo falla, el script
concluye — incorrectamente — que el proceso no es de Wazuh, lo da de baja, y
**aborta el resto de la secuencia de arranque** sin seguir con los demás
demonios (típicamente se corta justo después de `wazuh-execd`, y
`wazuh-agentd` —el que mantiene la conexión persistente con el manager—
nunca llega a arrancar; el agente queda registrado pero en estado *never
connected*).

**La corrección** — reemplazar `ps -p $PID` por `kill -0 $PID`, que verifica
la existencia del proceso sin depender de flags no estándar de `ps`:

```bash
sed -i 's/ps -p \$j > \/dev\/null 2>&1/kill -0 $j > \/dev\/null 2>\&1/' /var/ossec/bin/wazuh-control
sed -i 's/ps -p \${pid} > \/dev\/null 2>&1/kill -0 ${pid} > \/dev\/null 2>\&1/' /var/ossec/bin/wazuh-control

# Confirmar que ambas quedaron reemplazadas (deben aparecer como kill -0, no ps -p)
grep -n "ps -p\|kill -0" /var/ossec/bin/wazuh-control
```

Arrancar el agente:

```bash
/var/ossec/bin/wazuh-control stop
rm -f /var/ossec/var/run/*.pid
/var/ossec/bin/wazuh-control start
```

Deberían ver los 5-6 demonios (`wazuh-execd`, `wazuh-agentd`,
`wazuh-logcollector`, `wazuh-syscheckd`, `wazuh-modulesd`, etc.) arrancar
uno tras otro sin el mensaje `Process not used by Wazuh, removing`.
Confirmar:

```bash
ps aux | grep wazuh
tail -50 /var/ossec/logs/ossec.log
```

Y por último, confirmar en el **manager** que el agente ya no aparece como
*never connected* sino como **active**.

---
