package main

type (
	Proxy struct {
		Name string `toml:"name"`
		Url  string `toml:"url"`
	}

	Config struct {
		Listenaddr      string  `toml:"listenaddr"`
		Listenport      int     `toml:"listenport"`
		DNSresolver     string  `toml:"DNSresolver"`
		Timeout         int     `toml:"timeout"`
		CheckURL        string  `toml:"checkurl"`
		ProxyList       []Proxy `toml:"proxylist"`
		LogFile         string  `toml:"logfile"`
		DirectFile      string  `toml:"directfile"`
		ProxyFile       string  `toml:"proxyfile"`
		ClientsFile     string  `toml:"clientsfile"`
		BlockListPath   string  `toml:"blocklistpath"`
		BlockListBackup string  `toml:"blocklistbackup"`
		CheckDirect     bool    `toml:"checkdirect"`
	}

	Block_List []string
)

type HostItem struct {
	Host      string `json:"host"`
	Use_proxy bool   `json:"use_proxy"`
}
