package main

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	dns "github.com/Focinfi/go-dns-resolver"
	"github.com/magisterquis/connectproxy"
	"golang.org/x/net/proxy"
)

var (
	hosts_list         map[string]*HostItem
	hosts_list_mutex   = &sync.RWMutex{}
	clients_list       map[string]string
	adblock_list_mutex = &sync.RWMutex{}
	adblock_list       map[string]int
	myClient           *http.Client
	conf               Config
	//work_dir string
	exe_file    string
	ini_file    string
	dialerList  []proxy.Dialer
	dialer_best int
)

func mylog(text string) {
	if strings.Contains(text, CL_ESC) && conf.LogFile != "ansicon" {
		text = Strip(text)
	}
	log.Println(text)
}

/*
func save_host_list() {
    var file_name string = "hosts_list"
    if len(work_dir) > 0 {
        file_name = filepath.Join(work_dir, file_name)
    }
    hosts_list_mutex.RLock()
    buf, err := json.MarshalIndent(&hosts_list, "", "    ")
    hosts_list_mutex.RUnlock()
    if err != nil {
        mylog(err.Error())
        return
    }
    //fmt.Println(string(buf))
    err = ioutil.WriteFile(file_name, buf, 0666)
    if err != nil {
        mylog(err.Error())
    }
}

func save_ads_list() {
    var file_name string = "ads_list"
    if len(work_dir) > 0 {
        file_name = filepath.Join(work_dir, file_name)
    }
    var buf []byte
    var s string

    type kv struct {
        Key   string
        Value int
    }

    var ss []kv
    adblock_list_mutex.RLock()
    for k, v := range adblock_list {
        ss = append(ss, kv{k, v})
    }
    adblock_list_mutex.RUnlock()

    sort.Slice(ss, func(i, j int) bool {
        return ss[i].Value > ss[j].Value
    })

    for _, v := range ss {
        s = strconv.Itoa(v.Value) + "    " + v.Key + "\r\n"
        buf = append(buf, s...)
    }
    err := ioutil.WriteFile(file_name, buf, 0666)
    if err != nil {
        mylog(err.Error())
    }
}*/

func load_lists() {
	var p *HostItem
	var in bool
	var fileinfo os.FileInfo
	var file *os.File
	var err error
	var modifiedtime_direct_last time.Time = time.Date(2001, 11, 17, 20, 34, 58, 651387237, time.UTC)
	var modifiedtime_proxy_last time.Time = time.Date(2001, 11, 17, 20, 34, 58, 651387237, time.UTC)
	var modifiedtime_clients_last time.Time = time.Date(2001, 11, 17, 20, 34, 58, 651387237, time.UTC)
	var modifiedtime_own_last time.Time
	var modifiedtime_config_last time.Time
	/*var host_list_len_last int = 0
	  var ads_list_len_last int = 0*/
	var bAnyChanges = false

	hosts_list = map[string]*HostItem{}
	adblock_list = make(map[string]int)

	for {
		bAnyChanges = false

		fileinfo, err = os.Stat(ini_file)
		if err == nil {
			if modifiedtime_config_last.IsZero() {
				modifiedtime_config_last = fileinfo.ModTime()
			} else {
				if fileinfo.ModTime().After(modifiedtime_config_last) {
					mylog("Ini changed, exiting")
					os.Exit(3)
				}
			}
		}

		fileinfo, err = os.Stat(exe_file)
		if err == nil {
			if modifiedtime_own_last.IsZero() {
				modifiedtime_own_last = fileinfo.ModTime()
			} else {
				if fileinfo.ModTime().After(modifiedtime_own_last) {
					mylog("File changed, exiting")
					os.Exit(3)
				}
			}
		}

		if conf.ClientsFile != "" {
			fileinfo, err = os.Stat(conf.ClientsFile)
			if err == nil {
				if fileinfo.ModTime().After(modifiedtime_clients_last) {
					clients_list = nil
					clients_list = make(map[string]string)
					modifiedtime_clients_last = fileinfo.ModTime()
					file, _ = os.Open(conf.ClientsFile)
					if file != nil {
						scanner := bufio.NewScanner(file)
						for scanner.Scan() {
							t := scanner.Text()
							if strings.Contains(t, "=") {
								ts := strings.Split(t, "=")
								_, in = clients_list[strings.TrimSpace(ts[0])]
								if !in {
									clients_list[strings.TrimSpace(ts[0])] = strings.TrimSpace(ts[1])
									bAnyChanges = true
								}
							}
						}
						file.Close()
						scanner = nil
					}
				}
			}
		}

		/*fileinfo, err = os.Stat("adblock.txt")
		  if err == nil {
		      if modifiedtime_adblock_last.IsZero() {
		          modifiedtime_adblock_last = fileinfo.ModTime().Add( - time.Duration(1) * time.Second)
		      } else {
		          if fileinfo.ModTime().After(modifiedtime_adblock_last) {
		              adblock_list = nil
		              adblock_list = make(map[string]string)
		              modifiedtime_adblock_last = fileinfo.ModTime()
		              file, _ = os.Open("adblock.txt")
		              if file != nil {
		                  scanner := bufio.NewScanner(file)
		                  for scanner.Scan() {
		                      t := scanner.Text()
		                      adblock_list[strings.TrimSpace(t)] = "1"
		                      mylog("Added adblock " + t)
		                  }
		                  file.Close()
		                  scanner = nil
		              }
		          }
		      }
		  }*/

		if conf.DirectFile != "" {
			fileinfo, err = os.Stat(conf.DirectFile)
			if err == nil {
				if fileinfo.ModTime().After(modifiedtime_direct_last) {
					modifiedtime_direct_last = fileinfo.ModTime()
					file, _ = os.Open(conf.DirectFile)
					if file != nil {
						scanner := bufio.NewScanner(file)
						hosts_list_mutex.Lock()
						for scanner.Scan() {
							t := scanner.Text()
							if t[0:1] == "#" || len(t) == 0 {
								continue
							}
							if strings.Contains(t, "#") {
								t = strings.Split(t, "#")[0]
							}
							t = strings.TrimSpace(t)
							p, in = hosts_list[t]
							if !in {
								p = new(HostItem)
								p.Use_proxy = false
								p.Host = t
								hosts_list[t] = p
								mylog("Added direct " + t)
								bAnyChanges = true
							} else {
								if p.Use_proxy {
									p.Use_proxy = false
									mylog("Updated direct " + t)
									bAnyChanges = true
								}
							}
						}
						hosts_list_mutex.Unlock()
						file.Close()
						scanner = nil
					}
				}
			}
		}

		if conf.ProxyFile != "" {
			fileinfo, err = os.Stat(conf.ProxyFile)
			if err == nil {
				if fileinfo.ModTime().After(modifiedtime_proxy_last) {
					modifiedtime_proxy_last = fileinfo.ModTime()
					file, _ = os.Open(conf.ProxyFile)
					if file != nil {
						scanner := bufio.NewScanner(file)
						hosts_list_mutex.Lock()
						for scanner.Scan() {
							t := scanner.Text()
							if t[0:1] == "#" || len(t) == 0 {
								continue
							}
							if strings.Contains(t, "#") {
								t = strings.Split(t, "#")[0]
							}
							t = strings.TrimSpace(t)
							p, in = hosts_list[t]
							if !in {
								p = new(HostItem)
								p.Use_proxy = true
								p.Host = t
								hosts_list[t] = p
								mylog("Added proxy " + t)
								bAnyChanges = true
							} else {
								if !p.Use_proxy {
									p.Use_proxy = true
									mylog("Updated proxy " + t)
									bAnyChanges = true
								}
							}
						}
						hosts_list_mutex.Unlock()
						file.Close()
						scanner = nil
					}
				}
			}
		}

		/*if host_list_len_last != len(hosts_list) {
		      save_host_list()
		      host_list_len_last = len(hosts_list)
		  } else {
		      _, err = os.Stat("hosts_list")
		      if err != nil {
		          save_host_list()
		      }
		  }

		  if ads_list_len_last != len(adblock_list) {
		      save_ads_list()
		      ads_list_len_last = len(adblock_list)
		  } else {
		      _, err = os.Stat("ads_list")
		      if err != nil {
		          save_ads_list()
		      }
		  }*/

		if bAnyChanges {
			check_ads_list()
		}

		time.Sleep(time.Second * time.Duration(10))
	}
}

func getTimestamp() int64 {
	return time.Now().UnixNano() / 1e6
}

func check_direct(phost string) bool {
	var res *http.Response
	var err error
	var header string
	var cont_len int = 0
	var content []byte = nil

	req, _ := http.NewRequest(http.MethodGet, phost, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml")
	req.Header.Set("Accept-Charset", "ISO-8859-1,utf-8")
	//req.Header.Set("Host", "rezka.ag")
	req.Header.Set("Accept-Encoding", "none")
	req.Header.Set("Accept-Language", "ru-RU,ru;en-US,en;q=0.8")
	req.Header.Set("cache-control", "max-age=0")
	req.Header.Set("dnt", "1")
	req.Header.Set("pragma", "no-cache")

	var connStart = getTimestamp()

	res, _ = myClient.Do(req)
	//res, _ = http.Get(phost)
	var connTime = getTimestamp() - connStart
	if res != nil {
		if res.StatusCode == 307 && res.Request.Host == "blocked.mts.ru" {
			cont_len = 0
		} else if res.StatusCode != 403 {
			header = res.Header.Get("Content-Length")
			cont_len, err = strconv.Atoi(header)
			if err != nil {
				content, _ = io.ReadAll(res.Body)
				if strings.Contains(string(content), "blocked.mts.ru") {
					cont_len = 0
				} else {
					cont_len = len(string(content))
				}
			}
			cont_len = 200
		}
		res.Body.Close()
	} else {
		if connTime >= int64(conf.Timeout)*1000 {
			cont_len = 0
		} else {
			cont_len = 200
		}
		cont_len = 0
	}
	return cont_len > 10
}

func checkIPAddress(ip string) bool {
	if net.ParseIP(ip) == nil {
		//fmt.Printf("IP Address: %s - Invalid\n", ip)
		return false
	} else {
		//fmt.Printf("IP Address: %s - Valid\n", ip)
		return true
	}
}

func is_ads(phost string, premote string) bool {
	var host string = phost
	if strings.Contains(host, ":") {
		host = host[0:strings.Index(host, ":")]
	}
	// mylog(premote + " check adblock " + host)
	adblock_list_mutex.Lock()
	_, in := adblock_list[host]
	if in {
		mylog(CL_YELLOW + premote + CL_RESET + " adblock " + CL_RED + host + CL_RESET)
		adblock_list[host] += 1
	}
	adblock_list_mutex.Unlock()
	return in
}

func check_ads_list() {
	if conf.DNSresolver != "" {
		adblock_list_new := make(map[string]int)

		adblock_list_mutex.RLock()
		for r := range adblock_list {
			ipaddr := resolve(r)
			if ipaddr == "127.0.0.0" || ipaddr == "0.0.0.0" {
				adblock_list_new[r] = 1
			}
		}
		adblock_list_mutex.RUnlock()
		if len(adblock_list_new) < len(adblock_list) {
			adblock_list_mutex.Lock()
			adblock_list = nil
			adblock_list = adblock_list_new
			adblock_list_new = nil
			adblock_list_mutex.Unlock()
		}
	}
}

func resolve(phost string) string {
	var record string
	if results, err := dns.Exchange(phost, conf.DNSresolver, dns.TypeA); err == nil {
		for _, r := range results {
			// mylog(r.Record, r.Type, r.Ttl, r.Priority, r.Content)
			record = r.Content
			break
		}
	} else {
		mylog(err.Error())
	}
	return record
}

func is_use_proxy(phost string, premote string) int {

	var hosts []string
	var mainhost string
	var ipaddr string
	if strings.Contains(phost, ":") {
		hosts = strings.Split(phost, ":")
		hosts = hosts[:len(hosts)-1]
	} else {
		hosts = append(hosts, phost)
	}
	if !checkIPAddress(hosts[0]) {
		if conf.DNSresolver != "" {
			ipaddr = resolve(hosts[0])
			if ipaddr == "127.0.0.0" || ipaddr == "0.0.0.0" {
				adblock_list_mutex.Lock()
				_, in := adblock_list[hosts[0]]
				if in {
					adblock_list[hosts[0]] += 1
				} else {
					adblock_list[hosts[0]] = 1
				}
				adblock_list_mutex.Unlock()
				return -1
			}
		}
		hosts = strings.Split(hosts[0], ".")
		if len(hosts) > 1 {
			mainhost = hosts[len(hosts)-2] + "." + hosts[len(hosts)-1]
		} else {
			return -1
			// mainhost = hosts[0]
		}
	} else {
		mainhost = hosts[0]
	}
	var p *HostItem
	var in bool

	p, in = hosts_list[mainhost]
	if !in {
		// mylog("Check " + mainhost)
		p = new(HostItem)
		p.Host = phost
		p.Use_proxy = !check_direct("https://" + phost)
		hosts_list_mutex.Lock()
		hosts_list[mainhost] = p
		hosts_list_mutex.Unlock()
	}
	if p.Use_proxy {
		mylog(CL_YELLOW + premote + CL_LIGHT_CYAN + " proxy " + CL_RESET + phost)
	} else {
		mylog(CL_YELLOW + premote + CL_RESET + " direct " + phost)
	}
	if p.Use_proxy {
		return 1
	} else {
		return 0
	}
}

func get_client_name(premote string) string {
	var remote string = premote
	if strings.Contains(remote, ":") {
		remote = remote[0:strings.Index(remote, ":")]
	}
	s, in := clients_list[remote]
	if in {
		remote = s
	}
	return remote
}

func sel_best_dialer() {
	for {
		timeout := time.Duration(10 * time.Second)
		var test_url string = conf.CheckURL
		var min_time float64 = 999
		var min_index int = -1
		for i, p := range conf.ProxyList {
			proxyUrl, _ := url.Parse(p.Url)
			transport := http.Transport{}
			if strings.Contains(proxyUrl.Scheme, "socks") {
				dialSocksProxy, err := proxy.SOCKS5("tcp", proxyUrl.Host, nil, proxy.Direct)
				if err != nil {
					log.Println("Error connecting to proxy:", err)
					continue
				} else {
					transport.Dial = dialSocksProxy.Dial
				}
			} else {
				transport.Proxy = http.ProxyURL(proxyUrl)
			}
			transport.TLSClientConfig = &tls.Config{
				// See comment above.
				// UNSAFE!
				// DON'T USE IN PRODUCTION!
				InsecureSkipVerify: true}
			client := http.Client{}
			client.Timeout = timeout
			client.Transport = &transport
			start := time.Now()
			resp, err := client.Get(test_url)
			elapsed := time.Since(start).Seconds()
			if err == nil {
				log.Println(p.Name + " " + fmt.Sprintf("%0.2f", elapsed))
				if elapsed < min_time {
					min_time = elapsed
					min_index = i
				}
			} else {
				log.Println(p.Name + " no response " + err.Error())
			}
			if resp != nil {
				resp.Body.Close()
			}
		}
		if min_index != -1 && min_index != dialer_best {
			dialer_best = min_index
			log.Println("best dialer " + conf.ProxyList[dialer_best].Name)
		}
		time.Sleep(time.Second * time.Duration(600))
	}
}

func handleTunneling(w http.ResponseWriter, r *http.Request) {
	var remote_name string = get_client_name(r.RemoteAddr)
	/*if is_ads(r.Host, remote_name) {
		w.WriteHeader(http.StatusNoContent)
		return
	}*/
	var use_proxy int = 0
	if dialer_best != -1 {
		use_proxy = is_use_proxy(r.Host, remote_name)
	}

	var destConn net.Conn
	var err error
	switch use_proxy {
	case 0:
		destConn, err = net.DialTimeout("tcp", r.Host, 10*time.Second)
		if err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
	case 1:
		destConn, _ = dialerList[dialer_best].Dial("tcp", r.RequestURI) //net.Dial( "tcp" , address)
	default:
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
	if destConn != nil && clientConn != nil {
		go transfer(destConn, clientConn)
		go transfer(clientConn, destConn)
	} else {
		if destConn != nil {
			destConn.Close()
		}
		if clientConn != nil {
			clientConn.Close()
		}
	}
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func handleHTTP(w http.ResponseWriter, req *http.Request) {
	resp, err := http.DefaultTransport.RoundTrip(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func copyHeader(dst, src http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func main() {

	defer func() { //catch or finally
		if err := recover(); err != nil { //catch
			var f *os.File
			var s string = fmt.Sprintf("Exception: %v\n", err)
			fmt.Fprintf(os.Stderr, "%s", s)
			f, _ = os.Create("errors.txt")
			defer f.Close()
			_, _ = f.WriteString(s)
			os.Exit(1)
		}
	}()

	rand.Seed(time.Now().UnixNano())

	var fs os.FileInfo
	var err error

	exe_file = filepath.Base(os.Args[0])
	if strings.Contains(exe_file, "debug") {
		_, filename, _, _ := runtime.Caller(0)
		exe_file = filepath.Base(filename)
		if strings.Contains(exe_file, ".") {
			exe_file = strings.Split(exe_file, ".")[0] + filepath.Ext(os.Args[0])
		}
	}
	if strings.Contains(exe_file, ".") {
		ini_file = strings.Split(exe_file, ".")[0]
	}
	ini_file = ini_file + ".ini"
	if len(os.Args) == 2 {
		ini_file = os.Args[1]
	}
	if fs, err = os.Stat(ini_file); fs == nil || err != nil && errors.Is(err, os.ErrNotExist) {
		mylog("Error open file " + ini_file)
		os.Exit(1)
	}
	//work_dir = filepath.Dir(os.Args[0])
	_, err = toml.DecodeFile(ini_file, &conf)
	if err != nil {
		log.Panic(err)
		os.Exit(1)
	}

	var time_out time.Duration = time.Duration(conf.Timeout) * time.Second

	if conf.DNSresolver != "" {
		if !strings.Contains(conf.DNSresolver, ":") {
			conf.DNSresolver = conf.DNSresolver + ":53"
		}
		dns.Config.SetTimeout(uint(time.Second))
		dns.Config.RetryTimes = uint(4)
	}

	if len(conf.LogFile) > 0 {
		if conf.LogFile != "con" && conf.LogFile != "ansicon" {
			var logfile *os.File
			logfile, err = os.OpenFile(conf.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			defer logfile.Close()
			log.SetOutput(logfile)
		}
	} else {
		log.SetOutput(ioutil.Discard)
	}

	go load_lists()

	for _, p := range conf.ProxyList {
		var proxy_type string = p.Url
		var proxy_path string = proxy_type
		var http_url url.URL
		var dialer proxy.Dialer

		if strings.Contains(proxy_type, "://") {
			proxy_path = strings.Split(proxy_type, "://")[1]
		}

		if strings.Contains(proxy_type, "http://") {
			proxy_type = "http"
			http_url.Scheme = "http"
			http_url.Host = proxy_path
		} else {
			proxy_type = "socks"
		}
		switch proxy_type {
		case "socks":
			dialer, err = proxy.SOCKS5("tcp", proxy_path, nil, nil)
		case "http":
			dialer, err = connectproxy.New(&http_url, proxy.Direct)
		}
		if err != nil {
			log.Println(p.Name + " " + err.Error())
			//http.Error(err.Error(), http.StatusServiceUnavailable)
			//os.Exit(1)
		} else {
			dialerList = append(dialerList, dialer)
		}
	}
	dialer_best = -1

	if len(dialerList) > 1 {
		go sel_best_dialer()
	} else {
		dialer_best = 0
	}

	myClient = &http.Client{
		Timeout: time_out,
	}
	// _ = check_direct("https://sun7-3.userapi.com:443")
	// _ = is_use_proxy("tsn.ua", "_debug")
	// _ = is_use_proxy("rezka.ag", "_debug")
	//_ = is_use_proxy("gordonua.com", "_debug")
	_ = is_use_proxy("www.obozrevatel.com", "_debug")

	mylog("Listen at " + conf.Listenaddr + ":" + strconv.Itoa(conf.Listenport))
	server := &http.Server{
		Addr: conf.Listenaddr + ":" + strconv.Itoa(conf.Listenport),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodConnect {
				handleTunneling(w, r)
			} else {
				handleHTTP(w, r)
			}
		}),
		// Disable HTTP/2.
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
	}

	log.Fatal(server.ListenAndServe())
}
