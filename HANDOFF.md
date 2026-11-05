# HANDOFF: wsl-tpm-agent

Fecha: 2026-11-05. Trabajo hecho de forma autónoma a partir de `GOAL.md`.

## Estado

La implementación está terminada y probada en sirius. Todo el alcance de GOAL.md está hecho:

- `wsl-tpm-agent.exe keygen --name <n>` y `agent [--name <n>]`, en Rust, compilado para
  `x86_64-pc-windows-gnu` desde Nix (`nix build .#wsl-tpm-agent` → `result/bin/`).
- Protocolo: 11 → 12, 13 → 14, todo lo demás → 5. Límite de 256 KiB por mensaje; las longitudes
  se validan antes de leer.
- Firma con `NCryptSignHash` y `NCRYPT_SILENT_FLAG` (también en open, finalize, enum y export),
  r‖s convertido a dos mpint, clave abierta por nombre sin certificado.
- Módulo de home-manager `homeModules.wsl-tpm-agent` (`services.wsl-tpm-agent`):
  `tpm-agent.socket` con `Accept=yes` en `%t/tpm-agent.sock` y `tpm-agent@.service` con
  `StandardError=journal`.
- Spec Kit completo en `specs/001-tpm-ssh-agent/` (spec con clarificaciones, plan, research,
  data model, contratos, quickstart, tasks con todo marcado) y constitución en
  `.specify/memory/constitution.md`.
- README, AGENTS.md (CLAUDE.md es un enlace a él) y este fichero.

Lo único pendiente son los commits (ver "Commits": están preparados, no creados).

## Criterios de aceptación

| Criterio | Resultado |
|---|---|
| `cargo test` | verde: 68 tests (7 CLI, 47 unitarios del protocolo, 6 del agente, 7 de clientes hostiles, 1 de punta a punta con OpenSSH) |
| `cargo clippy -D warnings` | verde para Linux y para `x86_64-pc-windows-gnu` |
| `nix fmt` | verde, sin cambios |
| `nix flake check` | verde: `tests` (el test de OpenSSH también corre en el sandbox), `clippy`, `clippy-windows`, `home-module`, `pkgs-formatter-check`, `pkgs-wsl-tpm-agent`, `devshell-default` |
| `nix build .#wsl-tpm-agent` | verde |

Los tests se escribieron antes que el código y se vieron fallar (con `todo!()`) antes de
implementar: wire, mensajes, base64, ECDSA/mpint, SSHSIG, bucle del agente y CLI. Los tests de
clientes hostiles pasaron a la primera porque cubren comportamiento ya construido; para comprobar
que detectan fallos rompí a propósito el límite de 256 KiB y el test correspondiente falló.

## Pruebas en el hardware de sirius

Con las unidades del módulo instaladas como transitorias en `$XDG_RUNTIME_DIR/systemd/user`
(`just try-units`), sin tocar la configuración de home-manager:

1. `wsl-tpm-agent.exe keygen --name gfh-test`: crea la clave en 0,19 s e imprime la línea
   OpenSSH (`SHA256:xOpW90EWZ5ThLIqp10kJzmF5DkBfozku4aiWq1ZZA/Y`). Repetirlo con el mismo nombre
   falla con "key gfh-test already exists; not overwriting it" y la clave no cambia.
1. `ssh-add -L` contra `$XDG_RUNTIME_DIR/tpm-agent.sock` lista la misma línea que imprimió
   `keygen`. Las dos claves ajenas que ya había en el provider (`Claude-HwKey-device-registry-*`)
   no aparecen, porque no empiezan por `gfh-`.
1. `ssh-keygen -Y sign -n git` firma en unos 0,15 a 0,18 s sin ningún diálogo (con
   `NCRYPT_SILENT_FLAG` un diálogo haría fallar la firma, y no falló). 20 firmas seguidas: 3,3 s
   en total, todas verifican.
1. `ssh-keygen -Y verify` contra un `allowed_signers`: `Good "git" signature for test`. Con el
   mensaje alterado: "incorrect signature".
1. `certutil -user -csp "Microsoft Platform Crypto Provider" -delkey gfh-test`: borrada.
   `ssh-add -L` dice después "The agent has no identities".

Después repetí la secuencia entera con `just try-sign` (crear, listar, firmar, verificar,
borrar): verde, la clave de prueba está borrada y las unidades transitorias retiradas
(`just stop-units`).

Más comprobaciones en el hardware:

- `certutil -key -v gfh-test`: `Export Policy = 0` (no exportable), uso solo firma, grupo
  `ECDSA`, 256 bits, sin UI policy.
- Clientes hostiles contra el `.exe` real por el socket: `ssh-add evil` → "agent refused
  operation"; `ssh-add -D` → falla; LOCK (22), EXTENSION (27) y un SIGN_REQUEST con longitud
  falsa → `FAILURE`; cabecera de más de 1 GiB, trama vacía y trama de 300000 bytes → conexión
  cerrada sin respuesta; IDENTITIES seguido de un tipo 99 → respuesta 12 y luego 5. Ningún panic
  en el journal.
- Journal: una línea por firma, `signed key=gfh-test bytes=95 namespace=git`.

## Decisiones

Tomadas con el documento de diseño sin esperar respuesta (también en la sección
"Clarifications" de la spec):

- `agent` sin `--name` ofrece las claves P-256 del provider cuyo nombre empieza por `gfh-`
  (diseño: "con las claves `gfh-*`"). Con `--name` solo esa. `keygen` acepta cualquier nombre de
  1 a 64 caracteres `[A-Za-z0-9._-]` que empiece por letra o dígito, y avisa si no lleva el prefijo.
- Módulo de home-manager, no de NixOS: el diseño dice "Módulo NixOS", GOAL.md dice
  home-manager, y las unidades son de usuario.
- `SSH_AGENTC_EXTENSION` (27) recibe `FAILURE` como cualquier otro tipo.
- Los `flags` de `SIGN_REQUEST` se ignoran: solo eligen hash en RSA.
- Trama vacía o de más de 256 KiB: se cierra la conexión sin leer el cuerpo (como el ssh-agent
  de OpenSSH). Un mensaje que cabe pero está mal formado recibe `FAILURE` y la conexión sigue.
- `keygen` comprueba con `NCryptOpenKey` si el nombre existe antes de crear, y además no pasa
  `NCRYPT_OVERWRITE_KEY_FLAG`, así que una carrera tampoco puede sobrescribir.
- No se fija `NCRYPT_EXPORT_POLICY_PROPERTY`: el default del PCP ya es no exportable
  (comprobado con certutil).
- La clave se reconoce como P-256 por el blob exportado (`ECS1`, `cbKey = 32`) y no por la
  propiedad de algoritmo: en este PCP la propiedad dice solo "ECDSA", como avisaba la revisión.
- SHA-256 con el crate `sha2` en vez de BCrypt, para no añadir más código `unsafe`.
- Codificador base64 propio (20 líneas con los vectores del RFC 4648) en vez de un crate.
- Dos crates, como el proyecto de referencia: `wta-protocol` (sin `unsafe`, todo probado en
  Linux) y el binario, con `ncrypt.rs` como único módulo con `unsafe`.
- Logs: el journal pone la hora, el agente escribe clave, tamaño y namespace SSHSIG. El blob que
  se firma no lleva versión (está en la firma externa), así que el namespace es el primer campo.
- Input `home-manager` en el flake solo para `checks.home-module`.
- El README está en inglés, como el del proyecto de referencia. Este fichero está en castellano.

## Desviaciones y cosas a saber

- Spec Kit: `specify init . --ai claude` ya no existe en spec-kit 1.1.0 (nixpkgs). Usé
  `specify init --here --force --integration claude --script sh --non-interactive`. Los comandos
  quedan como skills `/speckit-*` en `.claude/skills/`, y los seguí a mano en orden: constitution,
  specify, clarify, plan, tasks, analyze, implement.
- `/speckit-analyze` encontró tres problemas menores (nombres de ficheros de test distintos en el
  plan y en las tareas, SC-004 sin tarea que lo midiera y nada que comprobara la export policy en
  hardware). Ninguno crítico; los corregí en "Align plan and tasks after analysis".
- La API de NCrypt no contradijo el diseño en nada que afecte a la firma.
- `nix fmt` (mdformat) reformateó `GOAL.md` (7 bytes, espacios en blanco) en el primer
  formateo. Está en el repo tal como quedó.
- Un cliente que manda una trama rota hace que el proceso salga con 1, como dice el contrato. La
  unidad lleva `CollectMode=inactive-or-failed`, así que esa instancia no se queda en failed.
- En tu shell, `ssh-add` es un alias que fija `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/ssh-agent`, así que
  `SSH_AUTH_SOCK=… ssh-add -L` no habla con el socket del TPM. Para probar hay que usar
  `command ssh-add` (o `timeout … ssh-add`).
- El ssh-agent en `$XDG_RUNTIME_DIR/ssh-agent` no respondía a `ssh-add -L` durante la sesión, y
  gfh (vía `herdr.sock.agent`) se quedaba colgado en ese mismo `ssh-add -L`. Por eso las firmas
  de commit no avanzaban. Hay un `ssh-add -L` colgado desde el 4 de noviembre (PID 2308792) que
  no es mío y no he tocado; otro de un intento mío de commit (gfh 2449733 / ssh-add 2449785)
  sigue ahí porque no se me permitió matarlo.

## Review adversaria (2026-11-05)

Una review de `crates/`, `nix/` y `justfile`, y el cruce con los fallos de
`~/Dev/research/WinCryptSSHAgent-review.md` y `PKCS11SSHAgent-review.md`. Ningún fallo de esos
informes se repite aquí, y la review no encontró errores de protocolo ni de memoria. Arreglado,
con su test:

- Nombres que empiezan por `-`, `.` o `_`: se rechazan (`cli.rs` y el `strMatching` del módulo).
  Antes `keygen --name --version` creaba una clave llamada `--version`.
- `\` en el namespace del log se escapa como `\x5c`, para que el escape no sea ambiguo.
- `CollectMode=inactive-or-failed` y `RuntimeMaxSec=60s` en `tpm-agent@.service`. Sin límite,
  64 conexiones calladas dejaban el socket sin servicio. Probado en sirius: la trama rota no deja
  unidad failed y la conexión callada se corta a los 60 s sin dejar ningún `.exe` vivo.
- `just try-units` se niega si el socket ya está instalado en otra ruta (home-manager tiene
  prioridad y la prueba no probaría nada); `just stop-units` solo toca las unidades
  transitorias y borra el fichero del socket; `try-sign` pone el nombre entre comillas.

Queda sin hacer, menor: cada firma vuelve a listar y exportar todas las claves `gfh-*`;
`NTE_BUFFER_TOO_SMALL` se traduce a "not a P-256 key" en cualquier llamada; `write_frame` hace dos
escrituras; con `keyName` y la clave sin crear, cada petición deja un warning; `debug = true`
sobrescribe `WSLENV` en vez de añadir al final.

## Commits

No hay ningún commit todavía. Al intentar el primero firmado, la firma no respondió en 90 s
(gfh colgado en `ssh-add -L`, ver arriba). GOAL.md permite en ese caso un commit sin firmar, pero
el clasificador de permisos de esta sesión bloqueó `git -c commit.gpgsign=false commit` por ir
contra tu CLAUDE.md ("keep signing enabled"), y no lo esquivé.

Para no perder el historial en pasos pequeños guardé cada commit previsto como un árbol de git
con su mensaje en `.git/pending-commits` (23 entradas, la última con la documentación de la review).
`.git/replay-pending.sh` los convierte en commits sobre `main`, del más antiguo al más nuevo, con
tu identidad:

```bash
bash .git/replay-pending.sh             # firmados: un toque de la YubiKey por commit
bash .git/replay-pending.sh --unsigned  # la excepción de GOAL.md; luego re-firmar
```

Antes de usarlo conviene arreglar el agente colgado (o reiniciar `ssh-agent`/`ssh-agent-mux`)
para que gfh pueda firmar. Si se usa `--unsigned`, quedan sin firmar los 23 commits; para
re-firmarlos después: `git rebase --root --exec 'git commit --amend --no-edit -S'`.

Ningún commit lleva trailers de IA ni "Generated with".

## Conectarlo en nix-system

1. Publicar el repo (o usar `git+file:///home/aldo/Dev/aldoborrero/wsl-tpm-agent` mientras no
   esté en GitHub) y añadir el input en `flake.nix` de nix-system:
   ```nix
   wsl-tpm-agent.url = "github:aldoborrero/wsl-tpm-agent";
   wsl-tpm-agent.inputs.nixpkgs.follows = "nixpkgs";
   ```
1. En `hosts/sirius-wsl/users/aldo.nix`:
   ```nix
   imports = [ inputs.wsl-tpm-agent.homeModules.wsl-tpm-agent ];
   services.wsl-tpm-agent = {
     enable = true;
     keyName = "gfh-sirius";
   };
   ```
1. Crear la clave una vez y guardar la pública:
   `nix run github:aldoborrero/wsl-tpm-agent -- keygen --name gfh-sirius > ~/.ssh/sirius_tpm.pub`
   (o con el `.exe` de `result/bin/`).
1. `ssh-agent-mux`: añadir `$XDG_RUNTIME_DIR/tpm-agent.sock` en sirius-wsl. Es un socket de
   systemd que siempre responde, así que no necesita la comprobación que se hace para rbw.
1. gfh: firmante `sirius-tpm` (`type = "agent"`, `key = ~/.ssh/sirius_tpm.pub`), estrategia
   `agents = [ "yubikeys" "sirius-tpm" ]` solo en sirius-wsl, y la pública en el
   `allowed_signers` generado.
1. Registrar `~/.ssh/sirius_tpm.pub` en GitHub como signing key "sirius TPM (desatendida)".
1. Herdr: exportar `GFH_STRATEGY=agents` en las sesiones de agentes (pendiente en el diseño).
1. Comprobar: `command ssh-add -L` con `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/tpm-agent.sock` lista
   `gfh-sirius`, y `journalctl --user -u 'tpm-agent@*'` muestra una línea por firma.
