# Explain TrustedSec `whoami`

## Objective

Analyze a popular public BOF and explain its real capability in operator language before running it.

<video class="bb-video-clip" controls preload="metadata" poster="../../assets/images/third-party-analysis.png">
  <source src="../../assets/media/third-party-analysis.webm" type="video/webm">
</video>

## Acquire or locate the corpus

```bash
bofbench arsenal acquire \
  https://github.com/trustedsec/CS-Situational-Awareness-BOF \
  --name trustedsec-sa
bofbench arsenal inventory arsenal/trustedsec-sa
```

Locate both object variants:

```bash
bofbench arsenal list arsenal/trustedsec-sa | rg 'whoami.*\.o'
```

## Analyze x64

```bash
bofbench analyze \
  arsenal/trustedsec-sa/SA/whoami/whoami.x64.o
```

The report should explain identity and token-context discovery. It should not promote an isolated token-query primitive into impersonation or alternate-token execution.

Representative interpretation:

```text
Can do
  inspect the current identity and token context
Effects
  reads identity and token metadata
Needs
  a Windows token in the current runtime context
```

## Compare x86

```bash
bofbench analyze \
  arsenal/trustedsec-sa/SA/whoami/whoami.x64.o \
  --compare arsenal/trustedsec-sa/SA/whoami/whoami.x86.o \
  --format md
```

Check behavioral equivalence before structural differences. The imports and relocation counts can differ while capability remains the same.

## Validate loader support

```bash
bofbench analyze \
  arsenal/trustedsec-sa/SA/whoami/whoami.x64.o \
  --loader-details
```

Loader compatibility means BOFBench can resolve and enter the object. Identity output still depends on the token of the native loader, Sliver session, or Beacon that executes it.

## Run when authorized

```bash
bofbench run \
  arsenal/trustedsec-sa/SA/whoami/whoami.x64.o \
  --via lab --lab devbox
```

Rerun analysis afterward to see exact-hash observed output. If the runtime object was rebuilt or patched, it receives a different observation record.

## Next steps

Search related token BOFs and compare actual behavior:

```bash
bofbench arsenal search arsenal/trustedsec-sa --can token
bofbench arsenal compare arsenal/trustedsec-sa --can token
```
