# Goal: implementar wsl-tpm-agent

Crea el proyecto `~/Dev/aldoborrero/wsl-tpm-agent`: un agente SSH (ssh-agent) que firma
con una clave guardada en el TPM de Windows y se usa desde WSL. Mañana tiene que estar
implementado, probado en el hardware real de sirius y con commits locales.

## Contexto (léelo antes de empezar)

- Diseño: `~/Dev/aldoborrero/nix-system/docs/plans/2026-11-03-firma-sin-yubikey-design.md`,
  secciones "Agente TPM", "Detalles de implementación" y "Alternativas descartadas".
- Por qué no reutilizamos lo que existe: `~/Dev/research/WinCryptSSHAgent-review.md` y
  `~/Dev/research/PKCS11SSHAgent-review.md`. No repitas sus errores: firmas ECDSA en
  r‖s sin convertir, escuchar en 0.0.0.0 sin autenticación, lecturas fuera de buffer,
  no usar NCRYPT_SILENT_FLAG, aceptar que cualquier cliente añada claves.
- Proyecto de referencia para el layout, el toolchain, el cross build a Windows y el flake:
  `~/Dev/aldoborrero/windows-fido-bridge/.worktrees/rename/wsl-fido-bridge`, en la rama
  `rename/wsl-fido-bridge`. Copia su estructura en lugar de inventar una nueva.
  Ese repo es de solo lectura: no lo modifiques.

## Alcance

- Un binario `wsl-tpm-agent.exe` en Rust, compilado para Windows desde Nix, con dos
  subcomandos:
  - `keygen --name <n>`: crea una clave ECDSA P-256 en el Microsoft Platform Crypto
    Provider. Si la clave ya existe, falla (no la sobrescribe). Imprime la clave pública
    en formato OpenSSH.
  - `agent [--name <n>]`: habla el protocolo ssh-agent por stdin/stdout, con una sola
    conexión por proceso. Mensajes:
    - REQUEST_IDENTITIES (11) → IDENTITIES_ANSWER (12)
    - SIGN_REQUEST (13) → SIGN_RESPONSE (14)
    - cualquier otro → FAILURE (5)
      Límite de 256 KiB por mensaje. Las longitudes se validan antes de leer.
- Firma con `NCryptSignHash` y `NCRYPT_SILENT_FLAG`. Convierte la firma P1363 (r‖s) a
  los dos mpint de SSH. Abre la clave por nombre, sin certificado X.509.
- Módulo de home-manager que exporta el repo: una unidad systemd `tpm-agent.socket`
  con `Accept=yes` en `$XDG_RUNTIME_DIR/tpm-agent.sock`, que lanza el `.exe` por
  interop. Los logs van al journal.
- Fuera de alcance: socket Hyper-V, TCP, servicio de Windows, añadir claves remotamente,
  RSA. No toques nix-system ni gfh.

## Proceso

1. Usa la skill `nix-project-scaffold` y después `nix-blueprint`. El flake debe ser de
   blueprint, con `packages`, `checks`, `devshell` y `modules/home`. Configura treefmt
   con la skill `nix-treefmt-formatter`.
1. Spec Kit: `nix shell nixpkgs#spec-kit -c specify init . --ai claude`. Después:
   1. `/speckit.constitution`: seguridad por defecto, sin superficie de red, mínimo
      código unsafe y con justificación, todo reproducible con Nix.
   1. `/speckit.specify`, tomando el contenido de este goal y del documento de diseño.
   1. `/speckit.clarify`. Resuelve tú las dudas con el diseño y deja escrita cada
      decisión. No te quedes esperando una respuesta.
   1. `/speckit.plan`, `/speckit.tasks`, `/speckit.analyze` y `/speckit.implement`.
1. TDD donde se pueda:
   - parser y serializer del protocolo, con tests de mensajes truncados o con
     longitudes falsas;
   - conversión de r‖s a mpint, con vectores conocidos, incluidos los casos de bit
     alto y de ceros a la izquierda;
   - un backend falso del TPM para probar el agente de punta a punta en Linux.
1. Escribe el README con la skill `crafting-effective-readmes`. Debe cubrir qué es,
   por qué existe (con un resumen de las alternativas descartadas), la instalación con
   Nix y home-manager, el uso, el modelo de seguridad y las limitaciones.
1. Pasa toda la prosa por la skill `humanizer`: README, specs y mensajes de commit.
   Nada de "Generated with" ni trailers de IA.

## Criterios de aceptación

- `cargo test`, `cargo clippy -D warnings`, `nix fmt`, `nix flake check` y
  `nix build .#wsl-tpm-agent` en verde.
- Prueba en el hardware real de sirius:
  1. `wsl-tpm-agent.exe keygen --name gfh-test`
  1. `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/tpm-agent.sock ssh-add -L` lista la clave.
  1. `ssh-keygen -Y sign` firma sin mostrar ningún diálogo.
  1. `ssh-keygen -Y verify` valida la firma contra un `allowed_signers`.
  1. Borra la clave de prueba al terminar.
- Un cliente que envía basura, mensajes enormes o una petición de añadir clave recibe
  FAILURE o se cierra la conexión, sin panic.

## Reglas

- Crea el repo git en local, en la rama `main`. No crees el repo en GitHub ni hagas push.
- Commits pequeños, con mensajes que describan solo el cambio y con mi identidad.
- Firma: intenta primero el commit firmado. Si falla porque la YubiKey no responde, haz
  ese commit sin firmar con `git -c commit.gpgsign=false commit ...` y sigue. Esta
  excepción vale solo para este repo y solo esta vez: no cambies la configuración de
  git. Apunta en `HANDOFF.md` qué commits quedaron sin firmar, para volver a firmarlos
  después.
- Si un detalle de la API de NCrypt contradice el diseño, prioriza que la firma sea
  correcta y documenta la desviación en `HANDOFF.md`.
- Al terminar, `HANDOFF.md` debe recoger: el estado de la implementación, los
  resultados de las pruebas en hardware, las decisiones que tomaste y los pasos para
  conectarlo en nix-system.
