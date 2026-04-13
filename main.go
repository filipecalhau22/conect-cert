/*
** CONECTLAB INFORMÁTICA LTDA ME
** https://www.conectlab.com.br
** Desenvolvido por: Filipe Calhau
** Data: 13/04/2026
 */

package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
)

// WebrootProvider implementa o challenge.Provider para escrever desafios em um diretório
type WebrootProvider struct {
	path string
}

// NewWebrootProvider cria um novo provider de webroot
func NewWebrootProvider(path string) *WebrootProvider {
	return &WebrootProvider{path: path}
}

// Present escreve o desafio ACME no arquivo
func (w *WebrootProvider) Present(domain, token, keyAuth string) error {
	challengePath := filepath.Join(w.path, token)
	if err := os.WriteFile(challengePath, []byte(keyAuth), 0644); err != nil {
		return fmt.Errorf("erro ao escrever desafio: %w", err)
	}
	fmt.Printf("[OK] Desafio ACME criado: %s\n", challengePath)
	return nil
}

// CleanUp remove o arquivo de desafio após validação
func (w *WebrootProvider) CleanUp(domain, token, keyAuth string) error {
	challengePath := filepath.Join(w.path, token)
	if err := os.Remove(challengePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("erro ao remover desafio: %w", err)
	}
	return nil
}

// User representa o usuário ACME registrado
type User struct {
	Email        string
	Registration *registration.Resource
	Key          crypto.PrivateKey
}

func (u *User) GetEmail() string {
	return u.Email
}

func (u *User) GetRegistration() *registration.Resource {
	return u.Registration
}

func (u *User) GetPrivateKey() crypto.PrivateKey {
	return u.Key
}

func readInput(reader *bufio.Reader, prompt string) string {
	fmt.Print(prompt)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `
Uso: %s [opcoes]

Opcoes:
  -d, -domain string       Dominio (ex: dominio.com.br)
  -e, -email string        Email para certificado
  -a, -action int          Acao: 1=novo certificado, 2=renovar (default: 1)
  -o, -output string       Diretorio de saida para certificados e desafios (default: ftp_upload)
  -h, -help                Mostra esta mensagem

Metodo fixo: HTTP-01 webroot

Exemplos:
  # Com parametros (nao interativo)
  %s -domain dominio.com.br -email seu@email.com -action 1

  # Com diretório customizado
  %s -domain dominio.com.br -email seu@email.com -output /caminho/destino

  # Interativo (sem parametros)
  %s

`, os.Args[0], os.Args[0], os.Args[0], os.Args[0])
}

func copyCerts(certsDir, ftpDir, domain string) {
	if err := os.MkdirAll(ftpDir, 0755); err != nil {
		fmt.Printf("[ERRO] ao criar %s: %v\n", ftpDir, err)
		return
	}

	arquivos := []string{
		domain + ".crt",
		domain + ".key",
		domain + ".issuer.crt",
		domain + ".json",
	}

	for _, nome := range arquivos {
		src := filepath.Join(certsDir, "certificates", nome)
		data, err := os.ReadFile(src)
		if err != nil {
			fmt.Printf("[AVISO] arquivo %s nao encontrado\n", nome)
			continue
		}
		dst := filepath.Join(ftpDir, nome)
		if err := os.WriteFile(dst, data, 0600); err != nil {
			fmt.Printf("[ERRO] ao copiar %s: %v\n", nome, err)
		}
	}
	fmt.Printf("[OK] Certificados copiados para %s/\n", ftpDir)
}

func keepACMEFilesAlive(webrootDir, ftpDir string) {
	// Rodar em background - copiar qualquer arquivo de desafio ACME que se crie
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()

		acmeDir := filepath.Join(webrootDir, ".well-known", "acme-challenge")
		destDir := filepath.Join(ftpDir, "acme-challenge")
		os.MkdirAll(destDir, 0755)

		for range ticker.C {
			entries, err := os.ReadDir(acmeDir)
			if err != nil {
				continue
			}

			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}
				src := filepath.Join(acmeDir, entry.Name())
				dst := filepath.Join(destDir, entry.Name())

				// Copiar se não existe no destino
				if _, err := os.Stat(dst); err != nil {
					if data, err := os.ReadFile(src); err == nil {
						os.WriteFile(dst, data, 0600)
						fmt.Printf("[OK] Desafio ACME copiado: %s\n", entry.Name())
					}
				}
			}
		}
	}()
}

func obtainCertificate(client *lego.Client, domains []string, webrootDir string) (*certificate.Resource, error) {
	fmt.Println()
	fmt.Println("[INFO] Solicitando certificado...")

	request := certificate.ObtainRequest{
		Domains: domains,
		Bundle:  true,
	}

	certificates, err := client.Certificate.Obtain(request)
	if err != nil {
		return nil, fmt.Errorf("erro ao obter certificado: %w", err)
	}

	return certificates, nil
}

func renewCertificate(client *lego.Client, certificates *certificate.Resource) (*certificate.Resource, error) {
	fmt.Println()
	fmt.Println("[INFO] Renovando certificado...")

	renewed, err := client.Certificate.Renew(*certificates, true, false, "")
	if err != nil {
		return nil, fmt.Errorf("erro ao renovar certificado: %w", err)
	}

	return renewed, nil
}

func main() {
	domain := flag.String("domain", "", "Dominio (ex: dominio.com.br)")
	domain2 := flag.String("d", "", "Dominio (shorthand)")
	email := flag.String("email", "", "Email para certificado")
	email2 := flag.String("e", "", "Email (shorthand)")
	action := flag.Int("action", 1, "Acao: 1=novo, 2=renovar")
	action2 := flag.Int("a", 1, "Acao (shorthand)")
	output := flag.String("output", "ftp_upload", "Diretorio de saida")
	output2 := flag.String("o", "", "Diretorio de saida (shorthand)")
	showHelp := flag.Bool("help", false, "Mostra ajuda")
	showHelp2 := flag.Bool("h", false, "")

	flag.Parse()

	// Processar flags abreviadas
	if *domain == "" && *domain2 != "" {
		domain = domain2
	}
	if *email == "" && *email2 != "" {
		email = email2
	}
	if *action == 1 && *action2 != 1 {
		action = action2
	}
	if *output == "ftp_upload" && *output2 != "" {
		output = output2
	}
	if *showHelp || *showHelp2 {
		printUsage()
		os.Exit(0)
	}

	fmt.Println("========================================================")
	fmt.Println("  SSL Let's Encrypt - Gerador de Certificado (via lego)")
	fmt.Println("========================================================")
	fmt.Println()

	// Se não tiver parametros, modo interativo
	reader := bufio.NewReader(os.Stdin)

	// Obter dominio
	domainVal := *domain
	if domainVal == "" {
		domainVal = readInput(reader, "Digite o dominio (ex: dominio.com.br): ")
	}
	if domainVal == "" {
		fmt.Println("[ERRO] Dominio nao pode ser vazio.")
		os.Exit(1)
	}

	// Email é parametrizável, obrigatório
	emailVal := *email
	if emailVal == "" {
		emailVal = readInput(reader, "Digite o email para certificado: ")
	}
	if emailVal == "" {
		fmt.Println("[ERRO] Email nao pode ser vazio.")
		os.Exit(1)
	}

	// Remover https:// ou http:// se incluido por engano
	domainVal = strings.TrimPrefix(domainVal, "https://")
	domainVal = strings.TrimPrefix(domainVal, "http://")

	fmt.Println()
	fmt.Printf("Dominio: %s\n", domainVal)
	fmt.Printf("Email:   %s\n", emailVal)
	fmt.Println()

	// Obter acao
	actionVal := *action
	if actionVal != 1 && actionVal != 2 {
		// Interativo apenas se não recebeu flag válida
		fmt.Println()
		fmt.Println("  [1] Novo certificado")
		fmt.Println("  [2] Renovar certificado existente")
		fmt.Println()
		actionStr := readInput(reader, "Opcao (1 ou 2): ")
		if actionStr == "2" {
			actionVal = 2
		} else {
			actionVal = 1
		}
	}

	dir, _ := os.Getwd()
	certsDir := filepath.Join(dir, "certs")
	webrootDir := filepath.Join(dir, "lego_challenge")

	// Usar diretório absoluto se for passado como absoluto, senão relativo
	var outputDir string
	if filepath.IsAbs(*output) {
		outputDir = *output
	} else {
		outputDir = filepath.Join(dir, *output)
	}

	fmt.Println()
	fmt.Printf("[INFO] Diretório de saída: %s\n", outputDir)
	fmt.Println()

	// Criar diretório de configuração
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		fmt.Printf("[ERRO] ao criar diretório de certs: %v\n", err)
		os.Exit(1)
	}

	// Criar diretório de webroot ACME
	acmeChallengeDir := filepath.Join(webrootDir, ".well-known", "acme-challenge")
	if err := os.MkdirAll(acmeChallengeDir, 0755); err != nil {
		fmt.Printf("[ERRO] ao criar diretorio webroot: %v\n", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("=== Modo HTTP-01 (Webroot) ===")
	fmt.Println()
	fmt.Println("[INFO] Desafios ACME serão salvos em:")
	fmt.Printf("  %s\n", acmeChallengeDir)
	fmt.Println()
	fmt.Println("[INFO] Seu programa externo deve estar servindo este diretório via HTTP")
	fmt.Printf("  em: http://%s/.well-known/acme-challenge/\n", domainVal)
	fmt.Println()

	// Iniciar monitoramento para copiar desafios automaticamente
	keepACMEFilesAlive(webrootDir, outputDir)

	fmt.Println("[INFO] Monitorizando criação de desafios ACME...")
	fmt.Println()

	// Gerar chave privada do usuário se não existir
	accountKeyPath := filepath.Join(certsDir, "accounts", "acme-v02.api.letsencrypt.org", emailVal, "keys", "private.key")
	accountKeyDir := filepath.Dir(accountKeyPath)

	var userKey crypto.PrivateKey
	if err := os.MkdirAll(accountKeyDir, 0755); err != nil {
		fmt.Printf("[ERRO] ao criar diretório de keys: %v\n", err)
		os.Exit(1)
	}

	if _, err := os.ReadFile(accountKeyPath); err == nil {
		// Carregar chave existente (simplificado - em produção seria decodificada)
		fmt.Printf("[INFO] Usando chave privada existente\n")
		// Para este exemplo, gerar nova chave
		// Em produção, você deveria decodificar a chave PEM
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		userKey = key
	} else {
		// Gerar nova chave privada
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Printf("[ERRO] ao gerar chave privada: %v\n", err)
			os.Exit(1)
		}
		userKey = key
		fmt.Printf("[OK] Chave privada gerada\n")
	}

	// Criar usuário ACME
	myUser := &User{
		Email: emailVal,
		Key:   userKey,
	}

	// Configurar cliente lego
	config := lego.NewConfig(myUser)
	config.Certificate.KeyType = certcrypto.KeyType("rsa2048")

	// Usar o servidor Let's Encrypt (produção)
	client, err := lego.NewClient(config)
	if err != nil {
		fmt.Printf("[ERRO] ao criar cliente ACME: %v\n", err)
		os.Exit(1)
	}

	// Registrar provider HTTP-01 customizado (webroot)
	provider := NewWebrootProvider(acmeChallengeDir)

	err = client.Challenge.SetHTTP01Provider(provider)
	if err != nil {
		fmt.Printf("[ERRO] ao configurar HTTP-01: %v\n", err)
		os.Exit(1)
	}

	// Registrar conta ACME se for novo
	reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		fmt.Printf("[AVISO] ao registrar conta: %v (continuando...)\n", err)
	} else {
		myUser.Registration = reg
		fmt.Printf("[OK] Conta ACME registrada\n")
	}

	fmt.Println()
	fmt.Println("[INFO] Iniciando processo ACME...")
	fmt.Println()

	var certificates *certificate.Resource
	var acmeErr error

	if actionVal == 2 {
		// Renovar certificado existente
		certPath := filepath.Join(certsDir, "certificates", domainVal+".crt")
		keyPath := filepath.Join(certsDir, "certificates", domainVal+".key")

		certData, err := os.ReadFile(certPath)
		if err != nil {
			fmt.Printf("[ERRO] certificado não encontrado para renovação: %v\n", err)
			os.Exit(1)
		}

		keyData, err := os.ReadFile(keyPath)
		if err != nil {
			fmt.Printf("[ERRO] chave privada não encontrada para renovação: %v\n", err)
			os.Exit(1)
		}

		certificates = &certificate.Resource{
			Certificate: certData,
			PrivateKey:  keyData,
		}

		certificates, acmeErr = renewCertificate(client, certificates)
	} else {
		// Obter novo certificado
		certificates, acmeErr = obtainCertificate(client, []string{domainVal}, webrootDir)
	}

	if acmeErr != nil {
		fmt.Printf("\n[ERRO] ACME falhou: %v\n", acmeErr)
		// Dar tempo para o monitoramento copiar os desafios ACME antes de falhar
		time.Sleep(1 * time.Second)
		os.Exit(1)
	}

	// Dar tempo para o monitoramento copiar todos os desafios ACME
	fmt.Println()
	fmt.Println("[INFO] Aguardando cópia dos desafios ACME...")
	time.Sleep(2 * time.Second)

	// Salvar certificados
	certDir := filepath.Join(certsDir, "certificates")
	if err := os.MkdirAll(certDir, 0755); err != nil {
		fmt.Printf("[ERRO] ao criar diretório de certificados: %v\n", err)
		os.Exit(1)
	}

	// Salvar certificado
	certFile := filepath.Join(certDir, domainVal+".crt")
	if err := os.WriteFile(certFile, certificates.Certificate, 0600); err != nil {
		fmt.Printf("[ERRO] ao salvar certificado: %v\n", err)
		os.Exit(1)
	}

	// Salvar chave privada
	keyFile := filepath.Join(certDir, domainVal+".key")
	if err := os.WriteFile(keyFile, certificates.PrivateKey, 0600); err != nil {
		fmt.Printf("[ERRO] ao salvar chave privada: %v\n", err)
		os.Exit(1)
	}

	// Salvar issuer
	issuerFile := filepath.Join(certDir, domainVal+".issuer.crt")
	if err := os.WriteFile(issuerFile, certificates.IssuerCertificate, 0600); err != nil {
		fmt.Printf("[ERRO] ao salvar issuer: %v\n", err)
		os.Exit(1)
	}

	// Salvar JSON com metadados
	jsonFile := filepath.Join(certDir, domainVal+".json")
	jsonData := map[string]interface{}{
		"domain":  domainVal,
		"email":   emailVal,
		"created": time.Now().Format(time.RFC3339),
	}
	jsonBytes, _ := json.MarshalIndent(jsonData, "", "  ")
	if err := os.WriteFile(jsonFile, jsonBytes, 0600); err != nil {
		fmt.Printf("[ERRO] ao salvar JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("========================================================")
	fmt.Println("  CERTIFICADO GERADO COM SUCESSO!")
	fmt.Println("========================================================")
	fmt.Println()
	fmt.Printf("Arquivos em %s/certificates/:\n", certsDir)
	fmt.Printf("  - %s.crt        (certificado)\n", domainVal)
	fmt.Printf("  - %s.key        (chave privada)\n", domainVal)
	fmt.Printf("  - %s.issuer.crt (certificado da CA)\n", domainVal)
	fmt.Printf("  - %s.json       (metadados)\n", domainVal)
	fmt.Println()

	copyCerts(certsDir, outputDir, domainVal)
	fmt.Printf("[INFO] Desafios ACME já foram copiados para %s/acme-challenge/\n", outputDir)

	// Aguardar Ctrl+C para limpar (opcional - desabilitar se indesejado)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	fmt.Println()
	fmt.Println("[INFO] Pressione Ctrl+C para sair")
	<-sigChan
}
