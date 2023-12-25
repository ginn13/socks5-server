package main

import (
	"log"
	"net/netip"
	"os"
	"github.com/armon/go-socks5"
	env "github.com/caarlos0/env/v6"
)

type params struct {
	User            string    `env:"PROXY_USER" envDefault:""`
	Password        string    `env:"PROXY_PASSWORD" envDefault:""`
	Port            string    `env:"PROXY_PORT" envDefault:"1080"`
	AllowedDestFqdn string    `env:"ALLOWED_DEST_FQDN" envDefault:""`
	AllowedIPs      []string  `env:"ALLOWED_IPS" envSeparator:"," envDefault:""`
	AllowedNets     []string `env:"ALLOWED_NETS" envSeparator:"," envDefault:""`
	ListenIP 		string 	  `env:"PROXY_LISTEN_IP" envDefault:"0.0.0.0"`
	RequireAuth		bool      `env:"REQUIRE_AUTH" envDefault:"true"`
}

func main() {
	// Working with app params
	cfg := params{}
	err := env.Parse(&cfg)
	if err != nil {
		log.Printf("%+v\n", err)
	}

	//Initialize socks5 config
	socks5conf := &socks5.Config{
		Logger: log.New(os.Stdout, "", log.LstdFlags),
	}

	if cfg.RequireAuth {
		if cfg.User == "" || cfg.Password == "" {
			log.Fatalln("Error: REQUIRE_AUTH is true, but PROXY_USER and PROXY_PASSWORD are not set.  The application will now exit.")
		}
		creds := socks5.StaticCredentials{
			cfg.User: cfg.Password,
		}
		cator := socks5.UserPassAuthenticator{Credentials: creds}
		socks5conf.AuthMethods = []socks5.Authenticator{cator}
	} else {
		log.Println("Warning: Running the proxy server without authentication. This is NOT recommended for public servers.")
	}

	if cfg.AllowedDestFqdn != "" {
		socks5conf.Rules = PermitDestAddrPattern(cfg.AllowedDestFqdn)
	}

	server, err := socks5.New(socks5conf)
	if err != nil {
		log.Fatal(err)
	}

	// Set IP whitelist
	if len(cfg.AllowedIPs) > 0 || len(cfg.AllowedNets) > 0 {
		whitelist := make([]netip.Addr, len(cfg.AllowedIPs))
		whitelistnet := make([]netip.Prefix, len(cfg.AllowedNets))

		if len(cfg.AllowedIPs) > 0 {
			for i, ip := range cfg.AllowedIPs {
				whitelist[i], _ = netip.ParseAddr(ip)
			}
		}
		if len(cfg.AllowedNets) > 0 {
			for i, inet := range cfg.AllowedNets {
				whitelistnet[i], _ = netip.ParsePrefix(inet)
			}
		}

		server.SetIPWhitelist(whitelist, whitelistnet)
	}

	listenAddr := ":" + cfg.Port
	if cfg.ListenIP != "" {
		listenAddr = cfg.ListenIP + ":" + cfg.Port
	}


	log.Printf("Start listening proxy service on %s\n", listenAddr)
	if err := server.ListenAndServe("tcp", listenAddr); err != nil {
		log.Fatal(err)
	}
}
