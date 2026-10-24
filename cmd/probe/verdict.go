package main

// EN: Plain-language verdict for a non-technical user (and for support reading the
// EN: report): what the ISP does and which way to connect. Pure function of the
// EN: measurements, so it is unit-tested without the network.
// RU: Вердикт простым языком: что делает провайдер и как подключаться.

import (
	"fmt"
	"strings"
)

// SiteVerdict is the per-site line from the mass scan ("Чисто", "DNS Spoofing", ...).
type SiteVerdict struct {
	Host   string
	Reason string
}

var siteNames = map[string]string{
	"youtube.com": "YouTube", "web.telegram.org": "Telegram Web", "discord.com": "Discord",
	"instagram.com": "Instagram", "twitter.com": "X (Twitter)",
}

// Verdict returns the lines shown to the user and sent to support, most important first.
func Verdict(r Reach, sites []SiteVerdict) []string {
	var out []string
	if len(r.VPN) > 0 {
		out = append(out, fmt.Sprintf("⚠ Включён VPN (%s): результат про туннель, а не про провайдера. Для диагностики выключите VPN и запустите снова.",
			strings.Join(r.VPN, ", ")))
	}

	// what the ISP does to foreign hosting
	cf, foreign := hostingStates(r.Hosting)
	switch {
	case foreign == "none":
		out = append(out, "Провайдер не пропускает данные к зарубежным хостингам (OVH, Hetzner, Vultr): соединение открывается, но ничего не приходит.")
	case foreign == "16kb":
		out = append(out, "Провайдер обрывает соединения с зарубежными хостингами после ~16 КБ (ТСПУ).")
	case foreign == "mixed":
		out = append(out, "Зарубежные хостинги открываются через раз: часть соединений режется.")
	}
	if cf != "ok" && cf != "" {
		out = append(out, "Cloudflare работает с перебоями — часть сайтов будет грузиться медленно или не до конца.")
	}

	// our server, per path
	tcpOK := r.Server != nil && r.Server.State() == "ok"
	hy2OK := r.Hy2 != nil && *r.Hy2
	udpOK := r.UDP != nil && *r.UDP
	if r.Server != nil {
		out = append(out, "Наш сервер: "+serverLine(r))
		out = append(out, "→ "+advice(tcpOK, hy2OK, udpOK, r.Hy2 != nil, r.UDP != nil))
	}

	// sites: informational
	var blocked []string
	for _, s := range sites {
		if s.Reason != "Чисто" {
			name := siteNames[s.Host]
			if name == "" {
				name = s.Host
			}
			blocked = append(blocked, name)
		}
	}
	if len(blocked) > 0 {
		out = append(out, "Без VPN провайдер блокирует: "+strings.Join(blocked, ", ")+". Это обычное дело, VPN это обходит.")
	} else if len(sites) > 0 && len(r.VPN) == 0 {
		out = append(out, "Проверенные сайты открываются и без VPN.")
	}
	return out
}

// hostingStates: Cloudflare state and the majority over the non-CDN hosts — one
// host can fail on its own (Hetzner fsn1 died 24.10), so one outlier is not a verdict.
func hostingStates(hs []Fetch) (cf, foreign string) {
	count := map[string]int{}
	n := 0
	for _, h := range hs {
		if h.Name == "Cloudflare" {
			cf = h.State()
			continue
		}
		count[h.State()]++
		n++
	}
	if n == 0 {
		return cf, ""
	}
	for _, st := range []string{"ok", "none", "16kb"} {
		if count[st]*2 > n {
			return cf, st
		}
	}
	return cf, "mixed"
}

func serverLine(r Reach) string {
	var parts []string
	switch r.Server.State() {
	case "ok":
		parts = append(parts, "TCP проходит")
	case "16kb":
		parts = append(parts, "TCP обрывается после 16 КБ")
	case "none":
		parts = append(parts, "TCP — данные не приходят")
	default:
		parts = append(parts, fmt.Sprintf("TCP — пришло %d КБ из 1000", r.Server.Bytes/1000))
	}
	if r.Hy2 != nil {
		parts = append(parts, map[bool]string{true: "Hysteria2 проходит", false: "Hysteria2 не проходит"}[*r.Hy2])
	}
	if r.UDP != nil {
		parts = append(parts, map[bool]string{true: "UDP проходит", false: "UDP не проходит"}[*r.UDP])
	}
	return strings.Join(parts, ", ")
}

// advice picks the connection way, cheapest for the user first.
func advice(tcp, hy2, udp, hy2Known, udpKnown bool) string {
	switch {
	case tcp && hy2:
		return "Подойдёт обычное подключение в Happ. Если тормозит — переключитесь на Hysteria2."
	case tcp:
		return "Подойдёт обычное подключение в Happ (VLESS Reality). Hysteria2 у вашего провайдера не работает — не выбирайте её."
	case hy2:
		return "Обычное подключение не пройдёт. В Happ выберите сервер с Hysteria2."
	case udp:
		return "Через Happ не пройдёт. Подойдёт Amnezia (AmneziaWG) — напишите нам, выдадим ключ."
	case !hy2Known || !udpKnown:
		return "Обычное подключение не пройдёт. Напишите нам — подберём другой способ."
	}
	return "До нашего сервера не проходит ничего. Нужен вход через российский сервер — напишите нам, мы на связи."
}
