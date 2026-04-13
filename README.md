# conect-cert - SSL Certificate Generator

Um gerador de certificados SSL/TLS automatizado usando **Let's Encrypt** e a biblioteca **lego**, com suporte ao método de validação HTTP-01 (webroot).

## 📋 Descrição

Este programa automatiza o processo de:
- ✅ Obter novos certificados SSL/TLS gratuitos via Let's Encrypt
- ✅ Renovar certificados existentes
- ✅ Usar validação HTTP-01 (webroot) para domínios
- ✅ Armazenar certificados, chaves privadas e metadados
- ✅ Copiar automaticamente desafios ACME para diretório específico

**Ideal para**: Servidores de aplicação, proxies reversos, e infra que precisa gerenciar certificados automaticamente.

---

## 🚀 Características

- **Modo Interativo**: Solicita domínio e email se não forem fornecidos como argumentos
- **Modo Não-Interativo**: Aceita todos os parâmetros via flags para automação
- **HTTP-01 Webroot**: Valida domínios colocando tokens em um diretório web
- **Monitoramento Automático**: Copia desafios ACME em tempo real para destino configurável
- **Gerenciamento de Chaves**: Reutiliza chaves de conta ACME se existirem
- **Metadados**: Salva informações do certificado em JSON

---

## 📦 Pré-requisitos

- **Go 1.16+** instalado
- Acesso ao diretório web do domínio (para servir desafios ACME)
- Permissões de escrita nos diretórios de saída
- Porta 80 acessível para validação HTTP (ou proxy reverso configurado)

---

## 🔧 Instalação e Compilação

### Clonar/Preparar o projeto

```bash
cd /caminho/do/projeto
go mod download
```

### Compilar

```bash
go build -o conect-cert main.go
```

### Executar

```bash
./conect-cert [opções]
```

---

## 💻 Como Usar

### Modo Interativo

Simplesmente execute sem argumentos:

```bash
./conect-cert
```

O programa perguntará:
1. Domínio (ex: `mail.viawork.com.br`)
2. Email para o certificado
3. Ação (1 = novo certificado, 2 = renovar)

### Modo Não-Interativo (com flags)

#### Obter novo certificado

```bash
./conect-cert -domain mail.viawork.com.br -email seu@email.com -action 1
```

#### Renovar certificado existente

```bash
./conect-cert -domain mail.viawork.com.br -email seu@email.com -action 2
```

#### Com diretório de saída customizado

```bash
./conect-cert -domain mail.viawork.com.br -email seu@email.com -action 1 -output /caminho/destino
```

### Flags Disponíveis

| Flag | Abreviada | Descrição | Padrão |
|------|-----------|-----------|--------|
| `-domain` | `-d` | Domínio do certificado (ex: mail.viawork.com.br) | - |
| `-email` | `-e` | Email para registro no Let's Encrypt | - |
| `-action` | `-a` | 1=novo certificado, 2=renovar | 1 |
| `-output` | `-o` | Diretório de saída para certificados e desafios | `ftp_upload` |
| `-help` | `-h` | Mostra mensagem de ajuda | - |

---

## 📂 Estrutura de Diretórios

Após executar, o programa cria a seguinte estrutura:

```
projeto/
├── certs/
│   ├── accounts/
│   │   └── acme-v02.api.letsencrypt.org/
│   │       └── seu@email.com/
│   │           └── keys/
│   │               └── private.key        # Chave privada da conta ACME
│   └── certificates/
│       ├── mail.viawork.com.br.crt       # Certificado
│       ├── mail.viawork.com.br.key       # Chave privada do domínio
│       ├── mail.viawork.com.br.issuer.crt # Certificado da CA
│       └── mail.viawork.com.br.json      # Metadados
│
├── lego_challenge/
│   └── .well-known/
│       └── acme-challenge/               # Desafios ACME (tokens)
│
└── ftp_upload/                           # Diretório de saída (customizável)
    ├── mail.viawork.com.br.crt
    ├── mail.viawork.com.br.key
    ├── mail.viawork.com.br.issuer.crt
    ├── mail.viawork.com.br.json
    └── acme-challenge/                   # Desafios copiados automaticamente
        └── (tokens de validação)
```

---

## 🔐 Como Funciona o HTTP-01 Validation

### Fluxo de Validação

1. **Programa gera tokens ACME** e os salva em:
   ```
   lego_challenge/.well-known/acme-challenge/
   ```

2. **Você deve servir este diretório via HTTP**:
   ```
   http://mail.viawork.com.br/.well-known/acme-challenge/
   ```

3. **Let's Encrypt acessa e valida** os tokens pelo caminho acima

4. **Programa copia automaticamente** os desafios para o `-output` configurado

### Exemplo com Nginx

Se usar Nginx como proxy reverso:

```nginx
server {
    listen 80;
    server_name mail.viawork.com.br;

    location /.well-known/acme-challenge/ {
        alias /caminho/do/projeto/lego_challenge/.well-known/acme-challenge/;
    }

    # Redirecionar HTTP para HTTPS após obter certificado
    location / {
        return 301 https://$server_name$request_uri;
    }
}
```

### Exemplo com Apache

```apache
<Directory "/caminho/do/projeto/lego_challenge/.well-known/acme-challenge">
    Require all granted
</Directory>

Alias "/.well-known/acme-challenge/" "/caminho/do/projeto/lego_challenge/.well-known/acme-challenge/"
```

---

## 📋 Exemplos Práticos

### Exemplo 1: Novo certificado para mail.viawork.com.br

```bash
./conect-cert \
  -domain mail.viawork.com.br \
  -email admin@viawork.com \
  -action 1 \
  -output /var/www/certs
```

**Resultado:**
- Certificado salvo em `/var/www/certs/mail.viawork.com.br.crt`
- Chave privada em `/var/www/certs/mail.viawork.com.br.key`
- Desafios ACME em `/var/www/certs/acme-challenge/`

### Exemplo 2: Modo interativo

```bash
./conect-cert
# Responder às perguntas:
# Digite o dominio: mail.viawork.com.br
# Digite o email: seu@email.com
# Opcao (1 ou 2): 1
```

### Exemplo 3: Renovação automática via cron

```bash
# /etc/cron.d/cert-renewal
0 2 * * * cd /home/usuario/conect-cert && ./conect-cert -domain mail.viawork.com.br -email seu@email.com -action 2 -output /var/www/certs 2>&1 | logger
```

---

## 🐛 Troubleshooting

### "Erro ao escrever desafio"

**Problema:** Permissão negada ao criar archivos de desafio

**Solução:**
```bash
chmod 755 lego_challenge/
chmod 755 lego_challenge/.well-known/
chmod 755 lego_challenge/.well-known/acme-challenge/
```

### "Let's Encrypt não consegue validar o domínio"

**Problema:** Tokens ACME não estão acessíveis via HTTP

**Verificar:**
```bash
# De outra máquina ou fora do servidor:
curl -I http://mail.viawork.com.br/.well-known/acme-challenge/

# Deve retornar 404 ou conteúdo do token, não 403/500
```

### "Certificado já existe"

Se receber erro ao renovar, verifique se os caminhos estão corretos:
```bash
ls -la certs/certificates/mail.viawork.com.br.*
```

### "Diretório de saída não encontrado"

```bash
# Criar diretório manualmente se necessário:
mkdir -p /caminho/do/output
chmod 755 /caminho/do/output
```

---

## 📝 Notas Importantes

- **Let's Encrypt Staging**: Para testes, use a biblioteca com `config.CADirURL = "https://acme-staging-v02.api.letsencrypt.org/directory"`
- **Rate Limits**: Let's Encrypt tem limites. Consulte: https://letsencrypt.org/en/docs/rate-limits/
- **Renovação**: Certificados Let's Encrypt são válidos por 90 dias. Renove com antecedência
- **Backup**: Salve copies das chaves privadas de forma segura
- **Permissões**: Mantenha arquivos `.key` com permissões `0600` (somente leitura do proprietário)

---

## 🔗 Recursos

- [Let's Encrypt](https://letsencrypt.org/)
- [lego Documentation](https://go-acme.github.io/lego/)
- [ACME Protocol](https://tools.ietf.org/html/rfc8555)
- [HTTP Challenge](https://letsencrypt.org/docs/challenges/#http-01-challenge)

---

## 📄 Licença

Verifique a documentação do projeto para detalhes de licença.

---

## ✅ Checklist de Deploy

- [ ] Go 1.16+ instalado
- [ ] Projeto compilado com `go build`
- [ ] Diretório web configurado para servir `.well-known/acme-challenge/`
- [ ] Porta 80 acessível para seu domínio
- [ ] Testado em staging antes de produção
- [ ] Permissões de arquivo configuradas corretamente
- [ ] Backups de chaves privadas salvas
- [ ] Renovação automática via cron configurada (opcional)
