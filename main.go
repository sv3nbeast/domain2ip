package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/schollz/progressbar/v3"
	"golang.org/x/sync/semaphore"
)

// CDN关键词列表
var cdnKeywords = []string{
	".cdn.", ".waf.", ".cloud.", ".edge.", ".akamai.",
	".fastly.", ".cloudfront.", ".cloudflare.", ".incapsula.",
	".sucuri.", ".stackpath.", ".limelight.", ".maxcdn.",
	".keycdn.", ".bunnycdn.", ".cdn77.", ".quantil.",
	".chinacache.", ".wangsu.", ".tcdn.", ".qiniu.",
	".upyun.", ".ksyun.", ".alicloud.", ".tencent-cloud.",
	".huaweicloud.", ".baidubce.", ".jdcloud.", ".ucloud.",
	".qingcloud.", ".qcloud.", ".aliyuncs.", ".myqcloud.",
	".cdn20.", ".cdn30.", ".cdn40.", ".cdn50.",
	".cdn60.", ".cdn70.", ".cdn80.", ".cdn90.",
	".cdn100.", ".cdn200.", ".cdn300.", ".cdn400.",
	".cdn500.", ".cdn600.", ".cdn700.", ".cdn800.",
	".cdn900.", ".cdn1000.",
}

// 结果结构体
type Result struct {
	URL    string
	Result string
}

// 检查IP是否为有效的IPv4
func isValidIPv4(ip string) bool {
	ipv4Regex := `^(\d{1,3}\.){3}\d{1,3}$`
	match, _ := regexp.MatchString(ipv4Regex, ip)
	if !match {
		return false
	}

	parts := strings.Split(ip, ".")
	for _, part := range parts {
		num := 0
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
			num = num*10 + int(c-'0')
		}
		if num < 0 || num > 255 {
			return false
		}
	}
	return true
}

// 检查域名是否包含CDN关键词
func isCDNDomain(domain string) bool {
	domain = strings.ToLower(domain)
	for _, keyword := range cdnKeywords {
		if strings.Contains(domain, keyword) {
			log.Printf("域名包含CDN关键词: %s -> %s", domain, keyword)
			return true
		}
	}
	return false
}

// 检查是否为CDN
func checkCDN(target string) bool {
	// 配置DNS解析器
	client := new(dns.Client)
	client.Timeout = 2 * time.Second

	// 检查A记录数量
	m := new(dns.Msg)
	m.SetQuestion(target+".", dns.TypeA)
	r, _, err := client.Exchange(m, "8.8.8.8:53")
	if err == nil && len(r.Answer) > 3 {
		log.Printf("域名 %s 有超过3个A记录,判定为CDN", target)
		return true
	}

	// 检查CNAME记录
	m = new(dns.Msg)
	m.SetQuestion(target+".", dns.TypeCNAME)
	r, _, err = client.Exchange(m, "8.8.8.8:53")
	if err == nil && len(r.Answer) > 0 {
		for _, ans := range r.Answer {
			if cname, ok := ans.(*dns.CNAME); ok {
				if isCDNDomain(cname.Target) {
					log.Printf("域名 %s 的CNAME %s 包含CDN关键词,判定为CDN", target, cname.Target)
					return true
				}
			}
		}
	}

	return false
}

// DNS解析配置
const (
	maxRetries     = 3
	dnsTimeout     = 5 * time.Second
	concurrentLimit = 20
)

// 域名转IP
func domain2ip2cdn(url string) Result {
	// 清理URL
	url = strings.TrimSpace(url)
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimSuffix(url, "/")

	if url == "" {
		log.Printf("无效的URL: %s", url)
		return Result{URL: url, Result: "failed"}
	}

	// 检查CDN关键词
	if isCDNDomain(url) {
		log.Printf("域名包含CDN关键词，直接标记为CDN: %s", url)
		return Result{URL: url, Result: "cdn"}
	}

	// 配置DNS解析器
	client := new(dns.Client)
	client.Timeout = dnsTimeout

	// 尝试解析A记录
	m := new(dns.Msg)
	m.SetQuestion(url+".", dns.TypeA)
	
	// 使用多个DNS服务器
	dnsServers := []string{
		"223.5.5.5:53",     // 阿里DNS
		"114.114.114.114:53", // 114DNS
	}

	var lastErr error
	for _, server := range dnsServers {
		for retry := 0; retry < maxRetries; retry++ {
			r, _, err := client.Exchange(m, server)
			if err != nil {
				lastErr = err
				time.Sleep(time.Second) // 重试前等待
				continue
			}

			if len(r.Answer) > 0 {
				for _, ans := range r.Answer {
					if a, ok := ans.(*dns.A); ok {
						ip := a.A.String()
						if isValidIPv4(ip) {
							if checkCDN(url) {
								log.Printf("发现CDN: %s", url)
								return Result{URL: url, Result: "cdn"}
							}
							log.Printf("成功解析IP: %s -> %s -> %s", url, ip, server)
							return Result{URL: url, Result: ip}
						}
					}
				}
			}
			break // 如果解析成功但没有结果，尝试下一个DNS服务器
		}
	}

	if lastErr != nil {
		log.Printf("解析失败: %s, 错误: %v", url, lastErr)
	} else {
		log.Printf("解析失败: %s, 无A记录", url)
	}
	return Result{URL: url, Result: "failed"}
}

// 读取URL文件
func readURL(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}
	return urls, scanner.Err()
}

// 写入结果到文件
func writeResults(results []Result, ipList, cList map[string]bool) error {
	filterSub, err := os.OpenFile("filterSubdomain.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer filterSub.Close()

	hostIP, err := os.OpenFile("host-ip.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer hostIP.Close()

	ipFile, err := os.OpenFile("ip.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer ipFile.Close()

	cFile, err := os.OpenFile("c.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer cFile.Close()

	for _, result := range results {
		switch result.Result {
		case "cdn":
			fmt.Fprintf(filterSub, "%s\n", result.URL)
			fmt.Fprintf(hostIP, "%s\t存在CDN\n", result.URL)
		case "failed":
			fmt.Fprintf(hostIP, "%s\t解析失败\n", result.URL)
			fmt.Fprintf(filterSub, "%s\n", result.URL)
		default:
			if !ipList[result.Result] {
				ipList[result.Result] = true
				parts := strings.Split(result.Result, ".")
				c := fmt.Sprintf("%s.%s.%s.0/24", parts[0], parts[1], parts[2])
				fmt.Fprintf(ipFile, "%s\n", result.Result)
				if !cList[c] {
					cList[c] = true
					fmt.Fprintf(cFile, "%s\n", c)
				}
			}
			fmt.Fprintf(hostIP, "%s\t%s\n", result.URL, result.Result)
		}
	}
	return nil
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("请提供URL文件路径")
	}

	urls, err := readURL(os.Args[1])
	if err != nil {
		log.Fatalf("读取URL文件失败: %v", err)
	}

	log.Printf("总共需要处理 %d 个URL", len(urls))

	// 创建进度条
	bar := progressbar.NewOptions(len(urls),
		progressbar.OptionSetDescription("处理进度"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "=",
			SaucerHead:    ">",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionShowCount(),
		progressbar.OptionShowIts(),
		progressbar.OptionSetWidth(50),
	)

	// 使用信号量控制并发
	sem := semaphore.NewWeighted(concurrentLimit)
	var wg sync.WaitGroup
	results := make(chan Result, len(urls))
	ipList := make(map[string]bool)
	cList := make(map[string]bool)
	batchResults := make([]Result, 0)
	batchSize := 100
	writeInterval := 500

	// 处理URL
	for i := 0; i < len(urls); i += batchSize {
		end := i + batchSize
		if end > len(urls) {
			end = len(urls)
		}
		batch := urls[i:end]

		log.Printf("开始处理第 %d 批，共 %d 个URL", i/batchSize+1, len(batch))

		for _, url := range batch {
			wg.Add(1)
			go func(url string) {
				defer wg.Done()
				if err := sem.Acquire(context.Background(), 1); err != nil {
					log.Printf("获取信号量失败: %v", err)
					return
				}
				defer sem.Release(1)
				results <- domain2ip2cdn(url)
				bar.Add(1) // 更新进度条
			}(url)
		}

		// 收集结果
		for j := 0; j < len(batch); j++ {
			result := <-results
			batchResults = append(batchResults, result)
		}

		// 定期写入文件
		if len(batchResults) >= writeInterval {
			log.Printf("达到写入阈值，开始写入文件")
			if err := writeResults(batchResults, ipList, cList); err != nil {
				log.Printf("写入文件失败: %v", err)
			}
			batchResults = batchResults[:0]
		}

		// 短暂休息
		time.Sleep(100 * time.Millisecond)
	}

	// 写入剩余结果
	if len(batchResults) > 0 {
		log.Printf("处理完成，写入剩余结果")
		if err := writeResults(batchResults, ipList, cList); err != nil {
			log.Printf("写入文件失败: %v", err)
		}
	}

	bar.Finish() // 完成进度条
	log.Printf("处理完成！")
	log.Printf("成功解析IP数量: %d", len(ipList))
	log.Printf("成功解析C段数量: %d", len(cList))
}
