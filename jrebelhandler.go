package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

func loggingRequest(r *http.Request) {
	query := r.URL.RawQuery
	if query != "" {
		query = "?" + query
	}

	logger.Infof("--> %s %s%s %s\n", r.Method, r.URL.Path, query, r.Proto)

	contentType := r.Header.Get("Content-Type")
	logger.Debugf("Content-Type: %s\n", contentType)
	logger.Debugf("Host: %s\n", r.Host)
	logger.Debugf("RemoteAddr: %s\n", r.RemoteAddr)
	logger.Debugf("User-Agent: %s\n", r.UserAgent())
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	loggingRequest(r)
	w.Header().Set("content-type", "text/html; charset=utf-8")
	w.WriteHeader(200)
	html := `
	 <html>
	 	<head>
			<title>Jrebel 激活服务</title>
	 	</head>
	 	<body>
			<h1>你好，这是 Jrebel 的激活服务器！</h1>
			<p>访问地址：<span class='host'></span>
			<p>JRebel 7.1 以及早期版本激活地址：<span class='host' style='color:red'></span>
			<p>JRebel 2018.1 以后激活地址：<span class='host' style='color:red'></span>
    			<p>邮箱为任意邮箱地址
       			<script>
	  			var host = window.location.origin;
      				document.getElementsByClassName('protocol')[0].innerHTML = protocol;
	  			document.getElementsByClassName('protocol')[1].innerHTML = protocol + '/{tokenname}';
       				document.getElementsByClassName('protocol')[2].innerHTML = protocol + '/%s';
	  		</script>
		 </body>
	 </html>
	`
	_, _ = fmt.Fprintf(w, html, newUUIDV4String())
}

func jrebelLeasesHandler(w http.ResponseWriter, r *http.Request) {
	loggingRequest(r)

	w.Header().Set("content-type", "application/json; charset=utf-8")

	parameter, err := getHttpBodyParameter(r)
	if err != nil {
		w.WriteHeader(403)
		_, _ = fmt.Fprintf(w, "%s\n", err)
		return
	}

	clientRandomness := parameter.Get("randomness")
	username := parameter.Get("username")
	guid := parameter.Get("guid")
	if clientRandomness == "" || username == "" || guid == "" {
		w.WriteHeader(403)
		_, _ = fmt.Fprint(w)
		return
	}
	offline, err := strconv.ParseBool(parameter.Get("offline"))
	if err != nil {
		// default true , for new jrebel version
		offline = config.OfflineDefault
	}

	validFrom := "null"
	validUntil := "null"
	var responseBody = jRebelLeases
	if offline {
		clientTime := parameter.Get("clientTime")
		offlineDays := parameter.Get("offlineDays")

		startTimeInt, err := strconv.ParseInt(clientTime, 10, 64)
		if err != nil {
			startTimeInt = int64(time.Now().Second()) * 1000
		}

		offlineDaysInt, err := strconv.ParseInt(offlineDays, 10, 64)
		if err != nil {
			offlineDaysInt = int64(config.OfflineDays)
		}

		// 过期时间
		expireTime := startTimeInt + (offlineDaysInt * 24 * 60 * 60 * 1000)
		responseBody.Offline = offline
		responseBody.ValidFrom = startTimeInt
		responseBody.ValidUntil = expireTime

		validFrom = clientTime
		validUntil = strconv.FormatInt(expireTime, 10)
	}

	serverRandomness := newServerRandomness()
	signature := toLeaseCreateJson(clientRandomness, serverRandomness, guid, offline, validFrom, validUntil)

	responseBody.ServerRandomness = serverRandomness
	responseBody.Signature = signature
	responseBody.Company = username

	response(w, &responseBody)
}

func jrebelLeases1Handler(w http.ResponseWriter, r *http.Request) {
	loggingRequest(r)

	w.Header().Set("content-type", "application/json; charset=utf-8")
	parameter, err := getHttpBodyParameter(r)
	if err != nil {
		w.WriteHeader(403)
		_, _ = fmt.Fprintf(w, "%s\n", err)
		return
	}
	username := parameter.Get("username")

	var responseBody = jrebelLeases1
	if username != "" {
		responseBody.Company = username
	}

	response(w, &responseBody)
}

func jrebelValidateHandler(w http.ResponseWriter, r *http.Request) {
	loggingRequest(r)

	w.Header().Add("content-type", "application/json; charset=utf-8")
	w.WriteHeader(200)
	_, _ = fmt.Fprintf(w, "%s\n", jrebelValidateJson)
}

func pingHandler(w http.ResponseWriter, r *http.Request) {
	loggingRequest(r)

	w.Header().Add("content-type", "text/html; charset=utf-8")
	parameter, err := getHttpBodyParameter(r)
	if err != nil {
		w.WriteHeader(403)
		_, _ = fmt.Fprintf(w, "%s\n", err)
		return
	}
	salt := parameter.Get("salt")
	if salt == "" {
		w.WriteHeader(403)
		_, _ = fmt.Fprint(w)
	} else {
		xmlContent := "<PingResponse><message></message><responseCode>OK</responseCode><salt>" + salt + "</salt></PingResponse>"
		signature, err := signWithMd5([]byte(xmlContent))
		if err != nil {
			w.WriteHeader(403)
			_, _ = fmt.Fprintf(w, "%s\n", err)
		} else {
			body := "<!-- " + hex.EncodeToString(signature) + " -->\n" + xmlContent
			w.WriteHeader(200)
			_, _ = fmt.Fprintf(w, "%s\n", body)
		}
	}
}

func obtainTicketHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "application/json; charset=utf-8")

	parameter, err := getHttpBodyParameter(r)
	if err != nil {
		responseError(w, err, 403)
		return
	}
	salt := parameter.Get("salt")
	username := parameter.Get("userName")
	prolongationPeriod := "607875500"
	if salt == "" || username == "" {
		w.WriteHeader(403)
		_, _ = fmt.Fprintln(w)
	} else {
		w.WriteHeader(200)
		xmlContent := "<ObtainTicketResponse><message></message><prolongationPeriod>" + prolongationPeriod + "</prolongationPeriod><responseCode>OK</responseCode><salt>" + salt + "</salt><ticketId>1</ticketId><ticketProperties>licensee=" + username + "\tlicenseType=0\t</ticketProperties></ObtainTicketResponse>"
		signature, err := signWithMd5([]byte(xmlContent))
		if err != nil {
			w.WriteHeader(403)
			_, _ = fmt.Fprintf(w, "%s\n", err)
		} else {
			body := "<!-- " + hex.EncodeToString(signature) + " -->\n" + xmlContent
			w.WriteHeader(200)
			_, _ = fmt.Fprintf(w, "%s\n", body)
		}
	}

}
func releaseTicketHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("content-type", "text/html; charset=utf-8")
	parameter, err := getHttpBodyParameter(r)
	if err != nil {
		responseError(w, err, 403)
		return
	}
	salt := parameter.Get("salt")
	if salt == "" {
		w.WriteHeader(403)
		_, _ = fmt.Fprintln(w)
	} else {
		xmlContent := "<ReleaseTicketResponse><message></message><responseCode>OK</responseCode><salt>" + salt + "</salt></ReleaseTicketResponse>"
		signature, err := signWithMd5([]byte(xmlContent))
		if err != nil {
			w.WriteHeader(403)
			_, _ = fmt.Fprintf(w, "%s\n", err)
		} else {
			body := "<!-- " + hex.EncodeToString(signature) + " -->\n" + xmlContent
			w.WriteHeader(200)
			_, _ = fmt.Fprintf(w, "%s\n", body)
		}
	}

}

func responseError(w http.ResponseWriter, err error, code int) {
	w.WriteHeader(403)
	_, _ = fmt.Fprintf(w, "%s\n", err)
}

func response(w http.ResponseWriter, resp interface{}) {
	bodyData, err := json.Marshal(&resp)
	if err != nil {
		w.WriteHeader(403)
		_, _ = fmt.Fprintf(w, "%s\n", err)
		return
	}
	w.WriteHeader(200)
	_, _ = fmt.Fprintf(w, "%s\n", string(bodyData))
}

func getHttpBodyParameter(r *http.Request) (params url.Values, err error) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return
	}
	s := string(body)
	ps := url.URL{
		Scheme:     "",
		Opaque:     "",
		User:       nil,
		Host:       "",
		Path:       "",
		RawPath:    "",
		ForceQuery: false,
		RawQuery:   s,
		Fragment:   "",
	}
	// fmt.Println(s)
	return ps.Query(), err
}
