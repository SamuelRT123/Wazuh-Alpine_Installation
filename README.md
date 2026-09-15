# Guía Wazuh en Alpine Linux

Guía técnica en LaTeX para compilar, instalar y registrar el agente de Wazuh 4.12.0 desde código fuente en Alpine Linux 3.21.5 (no soportado oficialmente por Wazuh, ya que usa `musl` en vez de `glibc`).

Este material fue elaborado para el curso de ciberseguridad de la Universidad de los Andes y es contenido original desarrollado por mí.

## Contenido

- `Debian_installation.md` — Pasos de instalación para sistemas Linux con distribución glibc.
- `Guia_Oficial_Instalación.md` — Guia de instalación de wazuh en Alpine linux en formato Markdown.
- `WazuhAlpine.pdf` — Guia de instalación de wazuh en Alpine linux en formato pdf/latex.

## Qué documenta

Cabeceras de compatibilidad musl/eBPF, parches de OpenSSL y símbolos glibc faltantes (`libexecinfo`, `libucontext`), compilación con `CMAKE_OPTS`, registro del agente contra el manager y troubleshooting (símbolos con `nm`/`objdump`, puertos 1515/1514, llaves vía API).

Verificado en vivo de punta a punta sobre Alpine 3.21.5 y Wazuh 4.12.0.
