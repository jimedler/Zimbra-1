
eUIAIAIEN ? nginx 0.8.48                                          03.08.2010

    *) eUIAIAIEA: OA?AOO ?I OIII?AIEA AEOAEOE?A server_name EIAAO UIA?AIEA 
       ?OOOIA EIN "".
       o?AOEAI cAIIAAEA iAEIIAAO.

    *) eUIAIAIEA: OA?AOO ?I OIII?AIEA AEOAEOE?A server_name_in_redirect 
       EIAAO UIA?AIEA off.

    *) aIAA?IAIEA: ?AOAIAIIUA $geoip_dma_code, $geoip_area_code E 
       $geoip_region_name.
       o?AOEAI Christine McGonagle.

    *) eO?OA?IAIEA: AEOAEOE?U proxy_pass, fastcgi_pass, uwsgi_pass E 
       scgi_pass IA IAOIAAI?AIEOO ? AIIEE limit_except.

    *) eO?OA?IAIEA: AEOAEOE?U proxy_cache_min_uses, fastcgi_cache_min_uses 
       uwsgi_cache_min_uses E scgi_cache_min_uses IA OAAIOAIE; IUEAEA 
       ?IN?EIAOO ? 0.8.46.

    *) eO?OA?IAIEA: AEOAEOE?A fastcgi_split_path_info IA?AOII EO?IIOUI?AIA 
       ?UAAIAIEN, AOIE ? ?UAAIAIEN ?I?AAAIA OIIOEI ?AOOO URI.
       o?AOEAI aOEA oAOAAAA E Frank Enderle.

    *) eO?OA?IAIEA: AEOAEOE?A rewrite IA UEOAIEOI?AIA OEI?II ";" ?OE 
       EI?EOI?AIEE EU URI ? AOCOIAIOU. 
       o?AOEAI Daisuke Murase.

    *) eO?OA?IAIEA: IIAOIO ngx_http_image_filter_module UAEOU?AI 
       OIAAEIAIEA, AOIE EUIAOAOAIEA AUII AIIOUA OAUIAOA image_filter_buffer.


eUIAIAIEN ? nginx 0.8.47                                          28.07.2010

    *) eO?OA?IAIEA: ?AOAIAIIAN $request_time EIAIA IA?AOIUA UIA?AIEN AIN 
       ?IAUA?OIOI?.

    *) eO?OA?IAIEA: IUEAEE, ?AOAE?A?AIIUA error_page, IA EUUEOI?AIEOO.

    *) eO?OA?IAIEA: AOIE EO?IIOUI?AION ?AOAIAOO max_size, OI cache manager 
       IIC UAAEEIEOOON; IUEAEA ?IN?EIAOO ? 0.8.46.


eUIAIAIEN ? nginx 0.8.46                                          19.07.2010

    *) eUIAIAIEA: AEOAEOE?U proxy_no_cache, fastcgi_no_cache, 
       uwsgi_no_cache E scgi_no_cache OA?AOO ?IENAO OIIOEI IA OIEOAIAIEA 
       UAEUUEOI?AIIICI IO?AOA.

    *) aIAA?IAIEA: AEOAEOE?U proxy_cache_bypass, fastcgi_cache_bypass, 
       uwsgi_cache_bypass E scgi_cache_bypass.

    *) eO?OA?IAIEA: nginx IA IO?IAIOAAI ?AINOO ? keys_zone EUUAE ? OIO?AA 
       IUEAEE OAAIOU O AUEAIAII: ?AINOO IO?IAIOAAIAOO OIIOEI ?I EOOA?AIEE 
       ?OAIAIE IAAEOE?IIOOE EIE ?OE IAAIOOAOEA ?AINOE.


eUIAIAIEN ? nginx 0.8.45                                          13.07.2010

    *) aIAA?IAIEA: OIO?UAIEN ? IIAOIA ngx_http_xslt_filter.
       o?AOEAI Laurence Rowe.

    *) eO?OA?IAIEA: IO?AO SSI IIAOIN IIC ?AOAAA?AOOON IA ?IIIIOOOA ?IOIA 
       EIIAIAU include O ?AOAIAOOII wait="yes"; IUEAEA ?IN?EIAOO ? 0.7.25. 
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: AEOAEOE?A listen IA ?IAAAOOE?AIA ?AOAIAOO setfib=0.


eUIAIAIEN ? nginx 0.8.44                                          05.07.2010

    *) eUIAIAIEA: OA?AOO nginx ?I OIII?AIEA IA EUUEOOAO IO?AOU AUEAIAI?, ? 
       UACIII?EA EIOIOUE AOOO OOOIEA "Set-Cookie".

    *) aIAA?IAIEA: AEOAEOE?A listen ?IAAAOOE?AAO ?AOAIAOO setfib.
       o?AOEAI aIAOAA ?EIIII?O.

    *) eO?OA?IAIEA: AEOAEOE?A sub_filter IICIA EUIAINOO OACEOOO AOE? ?OE 
       ?AOOE?III OI??AAAIEE.

    *) eO?OA?IAIEA: OI?IAOOEIIOOO O HP/UX.

    *) eO?OA?IAIEA: OI?IAOOEIIOOO O EII?EINOIOII AIX xcl_r.

    *) eO?OA?IAIEA: nginx O?EOAI AIIOUEA ?AEAOU SSLv2 EAE IAU?IUA OAEOOI?UA 
       UA?OIOU.
       o?AOEAI Miroslaw Jaworski.


eUIAIAIEN ? nginx 0.8.43                                          30.06.2010

    *) aIAA?IAIEA: OOEIOAIEA UACOOUEE AIIOUEE AAU geo-AEA?AUIII?.

    *) eO?OA?IAIEA: ?AOAIA?OA?IAIEA IUEAEE ? "location /zero {return 204;}" 
       AAU EUIAIAIEN EIAA IO?AOA IOOA?INII OAII IUEAEE; IUEAEA ?IN?EIAOO ? 
       0.8.42.

    *) eO?OA?IAIEA: nginx IIC UAEOU?AOO IPv6 listen OIEAO ?I ?OAIN 
       ?AOAEII?ECOOAAEE.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ?AOAIAIIOA $uid_set IIOII EO?IIOUI?AOO IA IAAIE OOAAEE 
       IAOAAIOEE UA?OIOA.


eUIAIAIEN ? nginx 0.8.42                                          21.06.2010

    *) eUIAIAIEA: OA?AOO nginx ?OI?AONAO location'U, UAAAIIUA OACOINOIUIE 
       ?UOAOAIENIE, AOIE UA?OIO ?IIIIOOOA OI??AI O location'II, UAAAIIUI 
       OOOIEIE ?OA?EEOA. ?OAAUAOYAA ?I?AAAIEA ?IN?EIIOO ? 0.7.1.

    *) aIAA?IAIEA: IIAOIO ngx_http_scgi_module.
       o?AOEAI Manlio Perillo.

    *) aIAA?IAIEA: ? AEOAEOE?A return IIOII AIAA?INOO OAEOO IO?AOA.


eUIAIAIEN ? nginx 0.8.41                                          15.06.2010

    *) aAUI?AOIIOOO: OAAI?EE ?OIAAOO nginx/Windows IIC UA?AOUAOOON A?AOEEII 
       ?OE UA?OIOA ?AEIA O IA?AOIIE EIAEOI?EIE UTF-8.

    *) eUIAIAIEA: OA?AOO nginx OAUOAUAAO EO?IIOUI?AOO ?OIAAIU ? OOOIEA 
       UA?OIOA.

    *) eO?OA?IAIEA: AEOAEOE?A proxy_redirect IA?OA?EIOII EUIAINIA OOOIEO 
       "Refresh" ? UACIII?EA IO?AOA AUEAIAA.
       o?AOEAI aIAOAA aIAOAA?O E iAEOEIO oICEIO.

    *) eO?OA?IAIEA: nginx IA ?IAAAOOE?AI ?OOO AAU EIAIE EIOOA ? OOOIEA 
       "Destination" ? UACIII?EA UA?OIOA.


eUIAIAIEN ? nginx 0.8.40                                          07.06.2010

    *) aAUI?AOIIOOO: OA?AOO nginx/Windows ECIIOEOOAO EIN ?IOIEA ?AEIA ?I 
       OIII?AIEA.
       o?AOEAI Jose Antonio Vazquez Gonzalez.

    *) aIAA?IAIEA: IIAOIO ngx_http_uwsgi_module.
       o?AOEAI Roberto De Ioris.

    *) aIAA?IAIEA: AEOAEOE?A fastcgi_param OI UIA?AIEAI, IA?EIAAYEION OI 
       OOOIEE "HTTP_", EUIAINAO OOOIEO UACIII?EA ? UA?OIOA EIEAIOA.

    *) eO?OA?IAIEA: OOOIEE "If-Modified-Since", "If-Range" E EI ?IAIAIUA ? 
       UACIII?EA UA?OIOA EIEAIOA ?AOAAA?AIEOO FastCGI-OAO?AOO ?OE 
       EUUEOI?AIEE.

    *) eO?OA?IAIEA: listen unix domain OIEAO IAIOUN AUII EUIAIEOO ?I ?OAIN 
       ?AOAEII?ECOOAAEE.
       o?AOEAI iAEOEIO aOIEIO.


eUIAIAIEN ? nginx 0.8.39                                          31.05.2010

    *) eO?OA?IAIEA: IAOIAAOAIAN AEOAEOE?A alias IA?OA?EIOII OAAIOAIA ?I 
       ?IIOAIIII location'A.

    *) eO?OA?IAIEA: ? EIIAEIAAEE AEOAEOE? alias O ?AOAIAIIUIE E try_files;

    *) eO?OA?IAIEA: listen unix domain E IPv6 OIEAOU IA IAOIAAI?AIEOO ?I 
       ?OAIN IAII?IAIEN AAU ?AOAOU?A.
       o?AOEAI iAEOEIO aOIEIO.


eUIAIAIEN ? nginx 0.8.38                                          24.05.2010

    *) aIAA?IAIEA: AEOAEOE?U proxy_no_cache E fastcgi_no_cache.

    *) aIAA?IAIEA: OA?AOO ?OE EO?IIOUI?AIEE ?AOAIAIIIE $scheme ? AEOAEOE?A 
       rewrite A?OIIAOE?AOEE AAIAAOON OAAEOAEO.
       o?AOEAI Piotr Sikora.

    *) eO?OA?IAIEA: OA?AOO UAAAOOEE ? AEOAEOE?A limit_req OIIO?AOOO?OAO 
       I?EOAIIIIO AICIOEOIO.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ?AOAIAIIOA $uid_got IAIOUN AUII EO?IIOUI?AOO ? SSI E 
       ?AOII?II IIAOINE.


eUIAIAIEN ? nginx 0.8.37                                          17.05.2010

    *) aIAA?IAIEA: IIAOIO ngx_http_split_clients_module.

    *) aIAA?IAIEA: AEOAEOE?A map ?IAAAOOE?AAO EIA?E AIIOUA 255 OEI?III?.

    *) eO?OA?IAIEA: nginx ECIIOEOI?AI UIA?AIEN "private" E "no-store" ? 
       OOOIEA "Cache-Control" ? UACIII?EA IO?AOA AUEAIAA.

    *) eO?OA?IAIEA: ?AOAIAOO stub ? SSI-AEOAEOE?A include IA EO?IIOUI?AION, 
       AOIE ?OOOIE IO?AO EIAI EIA 200.

    *) eO?OA?IAIEA: AOIE ?OIEOEOI?AIIUE EIE FastCGI UA?OIO ?IOOOAIIA 
       ?AOAIA?OA?INION ? AOOCIE ?OIEOEOI?AIIUE EIE FastCGI location, OI ? 
       OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault; IUEAEA ?IN?EIAOO 
       ? 0.8.33.
       o?AOEAI Yichun Zhang.

    *) eO?OA?IAIEA: OIAAEIAIEN IMAP E OAO?AOO Zimbra IICII UA?EOIOOO AI 
       OAEIAOOA.
       o?AOEAI Alan Batie.


eUIAIAIEN ? nginx 0.8.36                                          22.04.2010

    *) eO?OA?IAIEA: IIAOIO ngx_http_dav_module IA?OA?EIOII IAOAAAOU?AI 
       IAOIAU DELETE, COPY E MOVE AIN OEIIEIEI?.

    *) eO?OA?IAIEA: IIAOIO SSI ? ?IAUA?OIOAE EO?IIOUI?AI UAEUUEOI?AIIUA ? 
       IOII?III UA?OIOA UIA?AIEN ?AOAIAIIUE $query_string, $arg_... E EI 
       ?IAIAIUE.

    *) eO?OA?IAIEA: UIA?AIEA ?AOAIAIIIE ?I?OIOII UEOAIEOI?AIIOO ?IOIA 
       EAOAICI ?U?IAA SSI-EIIAIAU echo; IUEAEA ?IN?EIAOO ? 0.6.14.

    *) eO?OA?IAIEA: OAAI?EE ?OIAAOO UA?EOAI ?OE UA?OIOA ?AEIA FIFO.
       o?AOEAI Vicente Aguilar E iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: OI?IAOOEIIOOO O OpenSSL-1.0.0 IA 64-AEOIII Linux.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: nginx IA OIAEOAION O ?AOAIAOOII --without-http-cache; 
       IUEAEA ?IN?EIAOO ? 0.8.35.


eUIAIAIEN ? nginx 0.8.35                                          01.04.2010

    *) eUIAIAIEA: OA?AOO charset-?EIOOO OAAIOAAO AI SSI-?EIOOOA.

    *) aIAA?IAIEA: AEOAEOE?A chunked_transfer_encoding.

    *) eO?OA?IAIEA: OEI?II "&" ?OE EI?EOI?AIEE ? AOCOIAIOU ? ?OA?EIAE 
       rewrite IA UEOAIEOI?AION.

    *) eO?OA?IAIEA: nginx IIC UA?AOUAOOON A?AOEEII ?I ?OAIN IAOAAIOEE 
       OECIAIA EIE ?OE EO?IIOUI?AIEE AEOAEOE?U timer_resolution IA 
       ?IAO?IOIAE, IA ?IAAAOOE?AAYEE IAOIAU kqueue EIE eventport.
       o?AOEAI George Xie E iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: AOIE ?OAIAIIUA ?AEIU E ?IOOINIIIA IAOOI EOAIAIEN 
       OAO?IIACAIEOO IA OAUIUE ?AEII?UE OEOOAIAE, OI O ?IOOINIIUE ?AEII? 
       ?OAIN EUIAIAIEN AUII IA?AOIUI.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: IIAOIO ngx_http_memcached_module IIC ?UAA?AOO IUEAEO 
       "memcached sent invalid trailer".
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: nginx IA IIC OIAOAOO AEAIEIOAEO zlib-1.2.4 EU EOEIAIUE 
       OAEOOI?.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation fault, AOIE 
       ?AOAA IO?AOII FastCGI-OAO?AOA AUII IIICI ?U?IAA ? stderr; IUEAEA 
       ?IN?EIAOO ? 0.8.34.
       o?AOEAI iAEOEIO aOIEIO.


eUIAIAIEN ? nginx 0.8.34                                          03.03.2010

    *) eO?OA?IAIEA: nginx IA ?IAAAOOE?AI ?OA UE?OU, EO?IIOUOAIUA ? 
       EIEAIOOEEE OAOOE?EEAOAE.
       o?AOEAI eIIIEAIOEA aIEEAA?O.

    *) eO?OA?IAIEA: nginx IA?OA?EIOII EUUEOI?AI FastCGI-IO?AOU, AOIE ?AOAA 
       IO?AOII AUII IIICI ?U?IAA ? stderr.

    *) eO?OA?IAIEA: nginx IA ?IAAAOOE?AI HTTPS-OA?AOAOU.

    *) eO?OA?IAIEA: nginx/Windows IIC IA IAEIAEOO ?AEIU, AOIE ?OOO ? 
       EII?ECOOAAEE AUI UAAAI ? AOOCII OACEOOOA; IUEAEA ?IN?EIAOO ? 0.8.33.

    *) eO?OA?IAIEA: ?AOAIAIIAN $date_local ?UAA?AIA IA?AOIIA ?OAIN, AOIE 
       EO?IIOUI?AION ?IOIAO "%s".
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: AOIE ssl_session_cache IA AUI OOOAII?IAI EIE OOOAII?IAI 
       ? none, OI ?OE ?OI?AOEA EIEAIOOEICI OAOOE?EEAOU IICIA ?OIEOEIAEOO 
       IUEAEA "session id context uninitialized"; IUEAEA ?IN?EIAOO ? 0.7.1.

    *) eO?OA?IAIEA: geo-AEA?AUII ?IU?OAYAI UIA?AIEA ?I OIII?AIEA, AOIE 
       AEA?AUII ?EIA?AI ? OAAN IAIO E AIIAA OAOAE OAUIAOII /16 E IA 
       IA?EIAION IA COAIEAA OAOE OAUIAOII /16.

    *) eO?OA?IAIEA: AIIE, EO?IIOUOAIUE ? ?AOAIAOOA stub ? SSI-AEOAEOE?A 
       include, ?U?IAEION O MIME-OE?II "text/plain".

    *) eO?OA?IAIEA: $r->sleep() IA OAAIOAI; IUEAEA ?IN?EIAOO ? 0.8.11.


eUIAIAIEN ? nginx 0.8.33                                          01.02.2010

    *) aAUI?AOIIOOO: OA?AOO nginx/Windows ECIIOEOOAO ?OIAAIU ? EIIAA URI. 
       o?AOEAI Dan Crowley, Core Security Technologies.

    *) aAUI?AOIIOOO: OA?AOO nginx/Windows ECIIOEOOAO EIOIOEEA EIAIA ?AEII?. 
       o?AOEAI Dan Crowley, Core Security Technologies.

    *) eUIAIAIEA: OA?AOO keepalive OIAAEIAIEN ?IOIA UA?OIOI? POST IA 
       UA?OAYAAOON AIN MSIE 7.0+.
       o?AOEAI Adam Lounds.

    *) eUIAIAIEA: OA?AOO keepalive OIAAEIAIEN UA?OAYAIU AIN Safari.
       o?AOEAI Joshua Sierles.

    *) eO?OA?IAIEA: AOIE ?OIEOEOI?AIIUE EIE FastCGI UA?OIO ?IOOOAIIA 
       ?AOAIA?OA?INION ? AOOCIE ?OIEOEOI?AIIUE EIE FastCGI location, OI 
       ?AOAIAIIAN $upstream_response_time IICIA EIAOO IAIIOIAIOII AIIOUIA 
       UIA?AIEA; IUEAEA ?IN?EIAOO ? 0.8.7.

    *) eO?OA?IAIEA: ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault ?OE 
       IOAOAOU?AIEN OAIA UA?OIOA; IUEAEA ?IN?EIAOO ? 0.8.11.


eUIAIAIEN ? nginx 0.8.32                                          11.01.2010

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE EIAEOI?EE UTF-8 ? 
       ngx_http_autoindex_module.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: EIAII?AIIUA ?UAAIAIEN ? OACOINOIUE ?UOAOAIENE OAAIOAIE 
       OIIOEI AIN A?OE ?AOAIAIIUE.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: OA?AOO ? OOOIEA UACIII?EA UA?OIOA "Host" EO?IIOUOAOON 
       EIN "localhost", AOIE ? AEOAEOE?A auth_http OEAUAI unix domain 
       OIEAO.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: nginx IA ?IAAAOOE?AI ?AOAAA?O chunk'AIE AIN 201-UE 
       IO?AOI?.
       o?AOEAI Julian Reich.

    *) eO?OA?IAIEA: AOIE AEOAEOE?A "expires modified" ?UOOA?INIA AAOO ? 
       ?OIUIII, OI ? OOOIEA UACIII?EA IO?AOA "Cache-Control" ?UAA?AIIOO 
       IOOEAAOAIOIIA ?EOII.
       o?AOEAI aIAEOAA eA?OAII?O.


eUIAIAIEN ? nginx 0.8.31                                          23.12.2009

    *) aIAA?IAIEA: OA?AOO AEOAEOE?A error_page IIOAO ?AOAIA?OA?INOO IO?AOU 
       OI OOAOOOII 301 E 302.

    *) aIAA?IAIEA: ?AOAIAIIUA $geoip_city_continent_code, $geoip_latitude E 
       $geoip_longitude.
       o?AOEAI Arvind Sundararajan.

    *) aIAA?IAIEA: IIAOIO ngx_http_image_filter_module OA?AOO ?OACAA 
       OAAINAO EXIF E AOOCEA AAIIUA, AOIE IIE UAIEIAAO AIIOUA 5% ? 
       JPEG-?AEIA.

    *) eO?OA?IAIEA: nginx UAEOU?AI OIAAEIAIEA ?OE UA?OIOA UAEUUEOI?AIIICI 
       IO?AOA O ?OOOUI OAIII.
       o?AOEAI Piotr Sikora.

    *) eO?OA?IAIEA: nginx IIC IA OIAEOAOOON gcc 4.x ?OE EO?IIOUI?AIEE 
       I?OEIEUAAEE -O2 E ?UUA.
       o?AOEAI iAEOEIO aOIEIO E aAIEOO iAOU?I?O.

    *) eO?OA?IAIEA: OACOINOIUA ?UOAOAIEN ? location ?OACAA OAOOEOI?AIEOO O 
       O??OII OACEOOOA; IUEAEA ?IN?EIAOO ? 0.8.25.

    *) eO?OA?IAIEA: nginx EUUEOI?AI 304 IO?AO, AOIE ? UACIII?EA 
       ?OIEOEOOAIICI UA?OIOA AUIA OOOIEA "If-None-Match".
       o?AOEAI Tim Dettrick E David Kostal.

    *) eO?OA?IAIEA: nginx/Windows ?UOAION A?AOAU OAAIEOO ?OAIAIIUE ?AEI ?OE 
       ?AOAUA?EOE OOA OOYAOO?OAYACI ?AEIA.


eUIAIAIEN ? nginx 0.8.30                                          15.12.2009

    *) eUIAIAIEA: OA?AOO ?I OIII?AIEA OAUIAO AO?AOA AEOAEOE?U 
       large_client_header_buffers OA?AI 8K.
       o?AOEAI Andrew Cholakian.

    *) aIAA?IAIEA: ?AEI conf/fastcgi.conf AIN ?OIOOUE EII?ECOOAAEE FastCGI.

    *) eO?OA?IAIEA: nginx/Windows ?UOAION A?AOAU ?AOAEIAII?AOO ?OAIAIIUE 
       ?AEI ?OE ?AOAUA?EOE OOA OOYAOO?OAYACI ?AEIA.

    *) eO?OA?IAIEA: IUEAEE double free or corruption, ?IUIEEAAYAE, AOIE EIN 
       EIOOA IA AUII IAEAAII; IUEAEA ?IN?EIAOO ? 0.8.22.
       o?AOEAI eIIOOAIOEIO o?EOOO.

    *) eO?OA?IAIEA: ? EO?IIOUI?AIEE libatomic IA IAEIOIOUE ?IAO?IOIAE.
       o?AOEAI W-Mark Kubacki.


eUIAIAIEN ? nginx 0.8.29                                          30.11.2009

    *) eUIAIAIEA: OA?AOO AIN ?OIEOEOOAIUE IO?AOI? HTTP/0.9 ? IIC ?EUAOON 
       EIA IO?AOA "009".

    *) aIAA?IAIEA: AEOAEOE?U addition_types, charset_types, gzip_types, 
       ssi_types, sub_filter_types E xslt_types ?IAAAOOE?AAO ?AOAIAOO "*".

    *) aIAA?IAIEA: EO?IIOUI?AIEA ?OOOIAIIUE AOIIAOIUE I?AOAAEE GCC 4.1+.
       o?AOEAI W-Mark Kubacki.

    *) aIAA?IAIEA: ?AOAIAOO --with-libatomic[=DIR] ? configure.
       o?AOEAI W-Mark Kubacki.

    *) eO?OA?IAIEA: listen unix domain OIEAO EIAIE ICOAIE?AIIUA ?OA?A 
       AIOOO?A.

    *) eO?OA?IAIEA: UAEUUEOI?AIIUA IO?AOU IO?AOI? HTTP/0.9 IA?OA?EIOII 
       IAOAAAOU?AIEOO.

    *) eO?OA?IAIEA: EIAII?AIIUA ?UAAIAIEN ? OACOINOIUE ?UOAOAIENE, UAAAIIUA 
       EAE "?P<...>", IA OAAIOAIE ? AEOAEOE?A server_name.
       o?AOEAI iAEOEIO aOIEIO.


eUIAIAIEN ? nginx 0.8.28                                          23.11.2009

    *) eO?OA?IAIEA: nginx IA OIAEOAION O ?AOAIAOOII --without-pcre; IUEAEA 
       ?IN?EIAOO ? 0.8.25.


eUIAIAIEN ? nginx 0.8.27                                          17.11.2009

    *) eO?OA?IAIEA: OACOINOIUA ?UOAOAIEN IA OAAIOAIE ? nginx/Windows; 
       IUEAEA ?IN?EIAOO ? 0.8.25.


eUIAIAIEN ? nginx 0.8.26                                          16.11.2009

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE ?UAAIAIEE ? AEOAEOE?A rewrite; 
       IUEAEA ?IN?EIAOO ? 0.8.25.

    *) eO?OA?IAIEA: nginx IA OIAEOAION AAU ?AOAIAOOA --with-debug; IUEAEA 
       ?IN?EIAOO ? 0.8.25.


eUIAIAIEN ? nginx 0.8.25                                          16.11.2009

    *) eUIAIAIEA: OA?AOO ? IIC IUEAIE IA ?EUAOON OIIAYAIEA, AOIE ?AOAIAIIAN 
       IA IAEAAIA O ?IIIYOA IAOIAA $r->variable().

    *) aIAA?IAIEA: IIAOIO ngx_http_degradation_module.

    *) aIAA?IAIEA: EIAII?AIIUA ?UAAIAIEN ? OACOINOIUE ?UOAOAIENE.

    *) aIAA?IAIEA: OA?AOO ?OE EO?IIOUI?AIEE ?AOAIAIIUE ? AEOAEOE?A 
       proxy_pass IA OOAAOAOON UAAA?AOO URI.

    *) aIAA?IAIEA: OA?AOO AEOAEOE?A msie_padding OAAIOAAO E AIN Chrome.

    *) eO?OA?IAIEA: ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation fault ?OE 
       IAAIOOAOEA ?AINOE; IUEAEA ?IN?EIAOO ? 0.8.18.

    *) eO?OA?IAIEA: nginx ?AOAAA?AI OOAOUA IO?AOU EIEAIOAI, IA 
       ?IAAAOOE?AAYEI OOAOEA, ?OE IAOOOIEEAE gzip_static on E gzip_vary 
       off; IUEAEA ?IN?EIAOO ? 0.8.16.


eUIAIAIEN ? nginx 0.8.24                                          11.11.2009

    *) eO?OA?IAIEA: nginx ?OACAA AIAA?INI OOOIEO "Content-Encoding: gzip" ? 
       UACIII?IE 304-UE IO?AOI? IIAOIN ngx_http_gzip_static_module.

    *) eO?OA?IAIEA: nginx IA OIAEOAION AAU ?AOAIAOOA --with-debug; IUEAEA 
       ?IN?EIAOO ? 0.8.23.

    *) eO?OA?IAIEA: ?AOAIAOO "unix:" ? AEOAEOE?A set_real_ip_from 
       IA?OA?EIOII IAOIAAI?AION O ?OAAUAOYACI OOI?IN.

    *) eO?OA?IAIEA: ? resolver'A ?OE I?OAAAIAIEE ?OOOICI EIAIE.


eUIAIAIEN ? nginx 0.8.23                                          11.11.2009

    *) aAUI?AOIIOOO: OA?AOO SSL/TLS renegotiation UA?OAY?I.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: listen unix domain OIEAO IA IAOIAAI?AION ?I ?OAIN 
       IAII?IAIEN AAU ?AOAOU?A.

    *) eO?OA?IAIEA: ?AOAIAOO "unix:" ? AEOAEOE?A set_real_ip_from IA 
       OAAIOAI AAU AY? IAIIE AEOAEOE?U O IAAUI IP-AAOAOII.

    *) eO?OA?IAIEA: segmentation fault E UAAEEIE?AIEN ? resolver'A.

    *) eO?OA?IAIEA: ? resolver'A.
       o?AOEAI aOO?IO aIEAIO.


eUIAIAIEN ? nginx 0.8.22                                          03.11.2009

    *) aIAA?IAIEA: AEOAEOE?U proxy_bind, fastcgi_bind E memcached_bind.

    *) aIAA?IAIEA: AEOAEOE?U access E deny ?IAAAOOE?AAO IPv6.

    *) aIAA?IAIEA: AEOAEOE?A set_real_ip_from ?IAAAOOE?AAO IPv6 AAOAOA ? 
       UACIII?EAE UA?OIOA.

    *) aIAA?IAIEA: ?AOAIAOO "unix:" ? AEOAEOE?A set_real_ip_from.

    *) eO?OA?IAIEA: nginx IA OAAINI unix domain OIEAO ?IOIA OAOOEOI?AIEN 
       EII?ECOOAAEE.

    *) eO?OA?IAIEA: nginx OAAINI unix domain OIEAO ?I ?OAIN IAII?IAIEN AAU 
       ?AOAOU?A.

    *) eO?OA?IAIEA: I?AOAOIO "!-x" IA OAAIOAI.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault ?OE 
       EO?IIOUI?AIEE limit_rate ? HTTPS OAO?AOA.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ?OE UA?EOE ? IIC ?AOAIAIIIE $limit_rate ? OAAI?AI 
       ?OIAAOOA ?OIEOEIAEI segmentation fault.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault, 
       AOIE ?IOOOE AIIEA server IA AUII AEOAEOE?U listen; IUEAEA ?IN?EIAOO 
       ? 0.8.21.


eUIAIAIEN ? nginx 0.8.21                                          26.10.2009

    *) aIAA?IAIEA: OA?AOO EIA? -V ?IEAUU?AAO OOAOOO ?IAAAOOEE TLS SNI.

    *) aIAA?IAIEA: AEOAEOE?A listen IIAOIN HTTP ?IAAAOOE?AAO unix domain 
       OIEAOU.
       o?AOEAI Hongli Lai.

    *) aIAA?IAIEA: ?AOAIAOO "default_server" ? AEOAEOE?A listen.

    *) aIAA?IAIEA: OA?AOO ?AOAIAOO "default" IA IANUAOAIAI AIN OOOAII?EE 
       ?AOAIAOOI? listen-OIEAOA.

    *) eO?OA?IAIEA: nginx IA ?IAAAOOE?AI AAOU ? 2038 CIAO IA 32-AEOIUE 
       ?IAO?IOIAE;

    *) eO?OA?IAIEA: OOA?EE OIEAOI?; IUEAEA ?IN?EIAOO ? 0.8.11.


eUIAIAIEN ? nginx 0.8.20                                          14.10.2009

    *) eUIAIAIEA: OA?AOO ?I OIII?AIEA EO?IIOUOAOON OIAAOAYEA UE?OU SSL: 
       "HIGH:!ADH:!MD5".

    *) eO?OA?IAIEA: IIAOIO ngx_http_autoindex_module IA ?IEAUU?AI ?IOIAAIEE 
       OIUU AIN IEIEI? IA EAOAIICE; IUEAEA ?IN?EIAOO ? 0.7.15.

    *) eO?OA?IAIEA: nginx IA UAEOU?AI IIC, UAAAIIUE ?AOAIAOOII EII?ECOOAAEE 
       --error-log-path; IUEAEA ?IN?EIAOO ? 0.7.53.

    *) eO?OA?IAIEA: nginx IA O?EOAI UA?NOOA OAUAAIEOAIAI ? OOOIEA 
       "Cache-Control" ? UACIII?EA IO?AOA AUEAIAA.

    *) eO?OA?IAIEA: nginx/Windows IIC IA OIUAAOO ?OAIAIIUE ?AEI, ?AEI ? 
       EUUA EIE ?AEI O ?IIIYOA AEOAEOE? proxy/fastcgi_store, AOIE OAAI?EE 
       ?OIAAOO IA EIAI AIOOAOI?II ?OA? AIN OAAIOU O EAOAIICAIE ?AOEIACI 
       OOI?IN.

    *) eO?OA?IAIEA: OOOIEE "Set-Cookie" E "P3P" ? UACIII?EA IO?AOA 
       FastCGI-OAO?AOA IA OEOU?AIEOO ?OE EUUEOI?AIEE, AOIE IA 
       EO?IIOUI?AIEOO AEOAEOE?U fastcgi_hide_header O IAAUIE ?AOAIAOOAIE.

    *) eO?OA?IAIEA: nginx IA?AOII O?EOAI OAUIAO EUUA IA AEOEA.


eUIAIAIEN ? nginx 0.8.19                                          06.10.2009

    *) eUIAIAIEA: OA?AOO ?OIOIEII SSLv2 ?I OIII?AIEA UA?OAY?I.

    *) eUIAIAIEA: OA?AOO ?I OIII?AIEA EO?IIOUOAOON OIAAOAYEA UE?OU SSL: 
       "ALL:!ADH:RC4+RSA:+HIGH:+MEDIUM".

    *) eO?OA?IAIEA: AEOAEOE?A limit_req IA OAAIOAIA; IUEAEA ?IN?EIAOO ? 
       0.8.18.


eUIAIAIEN ? nginx 0.8.18                                          06.10.2009

    *) aIAA?IAIEA: AEOAEOE?A read_ahead.

    *) aIAA?IAIEA: OA?AOO IIOII EO?IIOUI?AOO IAOEIIOEI AEOAEOE? 
       perl_modules.

    *) aIAA?IAIEA: AEOAEOE?U limit_req_log_level E limit_conn_log_level.

    *) eO?OA?IAIEA: OA?AOO AEOAEOE?A limit_req OIIO?AOOO?OAO AICIOEOIO 
       leaky bucket.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: nginx IA OAAIOAI IA Linux/sparc.
       o?AOEAI Marcus Ramberg.

    *) eO?OA?IAIEA: nginx OIAI OEI?II '\0' ? OOOIEA "Location" ? UACIII?EA 
       ? IO?AOA IA UA?OIO MKCOL.
       o?AOEAI Xie Zhenye.

    *) eO?OA?IAIEA: ?IAOOI EIAA IO?AOA 499 ? IIC UA?EOU?AION EIA 0; IUEAEA 
       ?IN?EIAOO ? 0.8.11.

    *) eO?OA?IAIEA: OOA?EE OIEAOI?; IUEAEA ?IN?EIAOO ? 0.8.11.


eUIAIAIEN ? nginx 0.8.17                                          28.09.2009

    *) aAUI?AOIIOOO: OA?AOO OEI?IIU "/../" UA?OAYAIU ? OOOIEA "Destination" 
       ? UACIII?EA UA?OIOA.

    *) eUIAIAIEA: OA?AOO UIA?AIEA ?AOAIAIIIE $host ?OACAA ? IEOIAI OACEOOOA.

    *) aIAA?IAIEA: ?AOAIAIIAN $ssl_session_id.

    *) eO?OA?IAIEA: OOA?EE OIEAOI?; IUEAEA ?IN?EIAOO ? 0.8.11.


eUIAIAIEN ? nginx 0.8.16                                          22.09.2009

    *) aIAA?IAIEA: AEOAEOE?A image_filter_transparency.

    *) eO?OA?IAIEA: AEOAEOE?A "addition_types" AUIA IA?AOII IAU?AIA 
       "addtion_types".

    *) eO?OA?IAIEA: ?IO?E EUUA resolver'A.
       o?AOEAI Matthew Dempsky.

    *) eO?OA?IAIEA: OOA?EE ?AINOE ? resolver'A.
       o?AOEAI Matthew Dempsky.

    *) eO?OA?IAIEA: IA?AOIAN OOOIEA UA?OIOA ? ?AOAIAIIIE $request 
       UA?EOU?AIAOO ? access_log OIIOEI ?OE EO?IIOUI?AIEE error_log IA 
       OOI?IA info EIE debug.

    *) eO?OA?IAIEA: ? ?IAAAOOEA AIO?A-EAIAIA PNG ? IIAOIA 
       ngx_http_image_filter_module.

    *) eO?OA?IAIEA: nginx ?OACAA AIAA?INI OOOIEO "Vary: Accept-Encoding" ? 
       UACIII?IE IO?AOA, AOIE IAA AEOAEOE?U gzip_static E gzip_vary AUIE 
       ?EIA?AIU.

    *) eO?OA?IAIEA: ? ?IAAAOOEA EIAEOI?EE UTF-8 AEOAEOE?IE try_files ? 
       nginx/Windows.

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE post_action; IUEAEA ?IN?EIAOO 
       ? 0.8.11.
       o?AOEAI eCIOA aOOAIOA?O.


eUIAIAIEN ? nginx 0.8.15                                          14.09.2009

    *) aAUI?AOIIOOO: ?OE IAOAAIOEA O?AAEAIOII OIUAAIIICI UA?OIOA ? OAAI?AI 
       ?OIAAOOA IIC ?OIEUIEOE segmentation fault.
       o?AOEAI Chris Ries.

    *) eO?OA?IAIEA: AOIE AUIE I?EOAIU EIAIA .domain.tld, .sub.domain.tld E 
       .domain-some.tld, OI EIN .sub.domain.tld ?I?AAAII ?IA IAOEO 
       .domain.tld.

    *) eO?OA?IAIEA: ? ?IAAAOOEA ?OIUOA?IIOOE ? IIAOIA 
       ngx_http_image_filter_module.

    *) eO?OA?IAIEA: ? ?AEII?II AIO.

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE X-Accel-Redirect; IUEAEA 
       ?IN?EIAOO ? 0.8.11.

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE ?OOOIAIIICI ?AOIA; IUEAEA 
       ?IN?EIAOO ? 0.8.11.


eUIAIAIEN ? nginx 0.8.14                                          07.09.2009

    *) eO?OA?IAIEA: OOOAOA?UEE UAEUUEOI?AIIUE UA?OIO IIC UAIE?IOOO ? 
       OIOOINIEE "UPDATING".

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE error_log IA OOI?IA info EIE debug ? 
       OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault.
       o?AOEAI oAOCAA aI?AIEI?O.

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE ?OOOIAIIICI ?AOIA; IUEAEA 
       ?IN?EIAOO ? 0.8.11.

    *) eO?OA?IAIEA: AEOAEOE?A error_page IA ?AOAIA?OA?INIA IUEAEO 413; 
       IUEAEA ?IN?EIAOO ? 0.6.10.


eUIAIAIEN ? nginx 0.8.13                                          31.08.2009

    *) eO?OA?IAIEA: ? AEOAEOE?A "aio sendfile"; IUEAEA ?IN?EIAOO ? 0.8.12.

    *) eO?OA?IAIEA: nginx IA OIAEOAION AAU ?AOAIAOOA --with-file-aio IA 
       FreeBSD; IUEAEA ?IN?EIAOO ? 0.8.12.


eUIAIAIEN ? nginx 0.8.12                                          31.08.2009

    *) aIAA?IAIEA: ?AOAIAOO sendfile ? AEOAEOE?A aio ?I FreeBSD.

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE try_files; IUEAEA ?IN?EIAOO ? 
       0.8.11.

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE memcached; IUEAEA ?IN?EIAOO ? 
       0.8.11.


eUIAIAIEN ? nginx 0.8.11                                          28.08.2009

    *) eUIAIAIEA: OA?AOO AEOAEOE?A "gzip_disable msie6" IA UA?OAYAAO OOAOEA 
       AIN MSIE 6.0 SV1.

    *) aIAA?IAIEA: ?IAAAOOEA ?AEII?ICI AIO ?I FreeBSD E Linux.

    *) aIAA?IAIEA: AEOAEOE?A directio_alignment.


eUIAIAIEN ? nginx 0.8.10                                          24.08.2009

    *) eO?OA?IAIEA: OOA?AE ?AINOE ?OE EO?IIOUI?AIEE AAUU GeoIP City.

    *) eO?OA?IAIEA: IUEAEE ?OE EI?EOI?AIEE ?OAIAIIUE ?AEII? ? ?IOOINIIIA 
       IAOOI EOAIAIEN; IUEAEA ?IN?EIAOO ? 0.8.9.


eUIAIAIEN ? nginx 0.8.9                                           17.08.2009

    *) aIAA?IAIEA: OA?AOO OOAOOI?UE UACOOU?EE EUUA OAAIOAAO ? IOAAIOIII 
       ?OIAAOO; UOI AIIOII OIO?UEOO IAOAAIOEO AIIOUEE EUUAE.

    *) aIAA?IAIEA: OA?AOO ?OAIAIIUA ?AEIU E ?IOOINIIIA IAOOI EOAIAIEN IICOO 
       OAO?IIACAOOON IA OAUIUE ?AEII?UE OEOOAIAE.


eUIAIAIEN ? nginx 0.8.8                                           10.08.2009

    *) eO?OA?IAIEA: ? IAOAAIOEA UACIII?EI? IO?AOA, OAUAAI?IIUE ? 
       FastCGI-UA?EONE.

    *) eO?OA?IAIEA: AOIE UA?OIO IAOAAAOU?AION ? A?OE ?OIEOEOI?AIIUE EIE 
       FastCGI location'AE E ? ?AO?II EU IEE EO?IIOUI?AIIOO EUUEOI?AIEA, OI 
       ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation fault; IUEAEA ?IN?EIAOO ? 
       0.8.7.


eUIAIAIEN ? nginx 0.8.7                                           27.07.2009

    *) eUIAIAIEA: IEIEIAIOIAN ?IAAAOOE?AAIAN ?AOOEN OpenSSL - 0.9.7.

    *) eUIAIAIEA: ?AOAIAOO ask AEOAEOE?U ssl_verify_client EUIAI?I IA 
       ?AOAIAOO optional E OA?AOO II ?OI?AONAO EIEAIOOEEE OAOOE?EEAO, AOIE 
       II AUI ?OAAIIOAI.
       o?AOEAI Brice Figureau.

    *) aIAA?IAIEA: ?AOAIAIIAN $ssl_client_verify.
       o?AOEAI Brice Figureau.

    *) aIAA?IAIEA: AEOAEOE?A ssl_crl.
       o?AOEAI Brice Figureau.

    *) aIAA?IAIEA: ?AOAIAOO proxy AEOAEOE?U geo.

    *) aIAA?IAIEA: AEOAEOE?A image_filter ?IAAAOOE?AAO ?AOAIAIIUA AIN 
       UAAAIEN OAUIAOI?.

    *) eO?OA?IAIEA: EO?IIOUI?AIEA ?AOAIAIIIE $ssl_client_cert ?IOOEII 
       ?AINOO; IUEAEA ?IN?EIAOO ? 0.7.7.
       o?AOEAI oAOCAA oOOA?I??O.

    *) eO?OA?IAIEA: AEOAEOE?U proxy_pass_header E fastcgi_pass_header" IA 
       ?AOAAA?AIE EIEAIOO OOOIEE "X-Accel-Redirect", "X-Accel-Limit-Rate", 
       "X-Accel-Buffering" E "X-Accel-Charset" EU UACIII?EA IO?AOA 
       AUEAIAA.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ? IAOAAIOEA OOOIE "Last-Modified" E "Accept-Ranges" ? 
       UACIII?EA IO?AOA AUEAIAA; IUEAEA ?IN?EIAOO ? 0.7.44.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: IUEAEE "[alert] zero size buf" ?OE ?IIO?AIEE ?OOOUE 
       IO?AOU ? ?IAUA?OIOAE; IUEAEA ?IN?EIAOO ? 0.8.5.


eUIAIAIEN ? nginx 0.8.6                                           20.07.2009

    *) aIAA?IAIEA: IIAOIO ngx_http_geoip_module.

    *) eO?OA?IAIEA: XSLT-?EIOOO IIC ?UAA?AOO IUEAEO "not well formed XML 
       document" AIN ?OA?EIOIICI AIEOIAIOA.
       o?AOEAI Kuramoto Eiji.

    *) eO?OA?IAIEA: ? MacOSX, Cygwin E nginx/Windows ?OE ?OI?AOEA 
       location'I?, UAAAIIUE OACOINOIUI ?UOAOAIEAI, OA?AOO ?OACAA AAIAAOON 
       OOA?IAIEA AAU O??OA OACEOOOA OEI?III?.

    *) eO?OA?IAIEA: OA?AOO nginx/Windows ECIIOEOOAO OI?EE ? EIIAA URI.
       o?AOEAI Hugo Leisink.

    *) eO?OA?IAIEA: EIN ?AEIA OEAUAIIICI ? --conf-path ECIIOEOI?AIIOO ?OE 
       OOOAII?EA; IUEAEA ?IN?EIAOO ? 0.6.6.
       o?AOEAI iAEOEIO aOIEIO.


eUIAIAIEN ? nginx 0.8.5                                           13.07.2009

    *) eO?OA?IAIEA: OA?AOO nginx OAUOAUAAO ?IA??OEE?AIEN ? IAOIAA UA?OIOA.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE HTTP Basic-AOOAIOE?EEAAEE IA Windows 
       AIN IA?AOIUE EIAIE/?AOIIN ?IU?OAYAIAOO 500-AN IUEAEA.

    *) eO?OA?IAIEA: IO?AOU IIAOIN ngx_http_perl_module IA OAAIOAIE ? 
       ?IAUA?OIOAE.

    *) eO?OA?IAIEA: ? IIAOIA ngx_http_limit_req_module.
       o?AOEAI iAEOEIO aOIEIO.


eUIAIAIEN ? nginx 0.8.4                                           22.06.2009

    *) eO?OA?IAIEA: nginx IA OIAEOAION O ?AOAIAOOII --without-http-cache; 
       IUEAEA ?IN?EIAOO ? 0.8.3.


eUIAIAIEN ? nginx 0.8.3                                           19.06.2009

    *) aIAA?IAIEA: ?AOAIAIIAN $upstream_cache_status.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA MacOSX 10.6.

    *) eO?OA?IAIEA: nginx IA OIAEOAION O ?AOAIAOOII --without-http-cache; 
       IUEAEA ?IN?EIAOO ? 0.8.2.

    *) eO?OA?IAIEA: AOIE EO?IIOUI?AION ?AOAE?AO 401 IUEAEE IO AUEAIAA E 
       AUEAIA IA ?IU?OAYAI OOOIEO "WWW-Authenticate" ? UACIII?EA IO?AOA, OI 
       ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation fault.
       o?AOEAI a?CAIEA iU?II.


eUIAIAIEN ? nginx 0.8.2                                           15.06.2009

    *) eO?OA?IAIEA: ?I ?UAEIIAAEOO?EE open_file_cache E proxy/fastcgi EUUA 
       IA OOAOOA.

    *) eO?OA?IAIEA: open_file_cache IIC EUUEOI?AOO IOEOUOUA ?AEIU I?AIO 
       AIICI; IUEAEA ?IN?EIAOO ? 0.7.4.


eUIAIAIEN ? nginx 0.8.1                                           08.06.2009

    *) aIAA?IAIEA: ?AOAIAOO updating ? AEOAEOE?AE proxy_cache_use_stale E 
       fastcgi_cache_use_stale.

    *) eO?OA?IAIEA: OOOIEE "If-Modified-Since", "If-Range" E EI ?IAIAIUA ? 
       UACIII?EA UA?OIOA EIEAIOA ?AOAAA?AIEOO AUEAIAO ?OE EUUEOI?AIEE, AOIE 
       IA EO?IIOUI?AIAOO AEOAEOE?A proxy_set_header O IAAUIE ?AOAIAOOAIE.

    *) eO?OA?IAIEA: OOOIEE "Set-Cookie" E "P3P" ? UACIII?EA IO?AOA AUEAIAA 
       IA OEOU?AIEOO ?OE EUUEOI?AIEE, AOIE IA EO?IIOUI?AIEOO AEOAEOE?U 
       proxy_hide_header/fastcgi_hide_header O IAAUIE ?AOAIAOOAIE.

    *) eO?OA?IAIEA: IIAOIO ngx_http_image_filter_module IA ?IIEIAI ?IOIAO 
       GIF87a.
       o?AOEAI aAIEOO eIOEIUE.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA Solaris 10 E AIIAA OAIIEE; IUEAEA 
       ?IN?EIAOO ? 0.7.56.


eUIAIAIEN ? nginx 0.8.0                                           02.06.2009

    *) aIAA?IAIEA: AEOAEOE?A keepalive_requests.

    *) aIAA?IAIEA: AEOAEOE?A limit_rate_after.
       o?AOEAI Ivan Debnar.

    *) eO?OA?IAIEA: XSLT-?EIOOO IA OAAIOAI ? ?IAUA?OIOAE.

    *) eO?OA?IAIEA: IAOAAIOEA IOIIOEOAIOIUE ?OOAE ? nginx/Windows.

    *) eO?OA?IAIEA: ? proxy_store, fastcgi_store, proxy_cache E 
       fastcgi_cache ? nginx/Windows.

    *) eO?OA?IAIEA: ? IAOAAIOEA IUEAIE ?UAAIAIEN ?AINOE.
       o?AOEAI iAEOEIO aOIEIO E eEOEIIO eIOEIOEIIO.


eUIAIAIEN ? nginx 0.7.59                                          25.05.2009

    *) aIAA?IAIEA: AEOAEOE?U proxy_cache_methods E fastcgi_cache_methods.

    *) eO?OA?IAIEA: OOA?EE OIEAOI?; IUEAEA ?IN?EIAOO ? 0.7.25.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?AOAIAIIIE $request_body ? OAAI?AI 
       ?OIAAOOA ?OIEOEIAEI segmentation fault, AOIE ? UA?OIOA IA AUII OAIA; 
       IUEAEA ?IN?EIAOO ? 0.7.58.

    *) eO?OA?IAIEA: SSL-IIAOIE IICIE IA OIAEOAOOON IA Solaris E Linux; 
       IUEAEA ?IN?EIAOO ? 0.7.56.

    *) eO?OA?IAIEA: IO?AOU IIAOIN ngx_http_xslt_filter_module IA 
       IAOAAAOU?AIEOO SSI-, charset- E gzip-?EIOOOAIE.

    *) eO?OA?IAIEA: AEOAEOE?A charset IA OOA?EIA EIAEOI?EO AIN IO?AOI? 
       IIAOIN ngx_http_gzip_static_module.


eUIAIAIEN ? nginx 0.7.58                                          18.05.2009

    *) aIAA?IAIEA: AEOAEOE?A listen ?I?OI?ICI ?OIEOE-OAO?AOA ?IAAAOOE?AAO 
       IPv6.

    *) aIAA?IAIEA: AEOAEOE?A image_filter_jpeg_quality.

    *) aIAA?IAIEA: AEOAEOE?A client_body_in_single_buffer.

    *) aIAA?IAIEA: ?AOAIAIIAN $request_body.

    *) eO?OA?IAIEA: ? IIAOIA ngx_http_autoindex_module ? OOUIEAE IA EIAIA 
       ?AEII?, OIAAOOAYEE OEI?II ":".

    *) eO?OA?IAIEA: ?OIAAAOOA "make upgrade" IA OAAIOAIA; IUEAEA ?IN?EIAOO 
       ? 0.7.53.
       o?AOEAI aAIEOO iAOU?I?O.


eUIAIAIEN ? nginx 0.7.57                                          12.05.2009

    *) eO?OA?IAIEA: ?OE ?AOAIA?OA?IAIEE IUEAIE IIAOIN 
       ngx_http_image_filter_module ? EIAII?AIIUE location ? OAAI?AI 
       ?OIAAOOA ?OIEOEIAEI floating-point fault; IUEAEA ?IN?EIAOO ? 0.7.56.


eUIAIAIEN ? nginx 0.7.56                                          11.05.2009

    *) aIAA?IAIEA: nginx/Windows ?IAAAOOE?AAO IPv6 ? AEOAEOE?A listen 
       IIAOIN HTTP.

    *) eO?OA?IAIEA: ? IIAOIA ngx_http_image_filter_module.


eUIAIAIEN ? nginx 0.7.55                                          06.05.2009

    *) eO?OA?IAIEA: ?AOAIAOOU http_XXX ? AEOAEOE?AE proxy_cache_use_stale E 
       fastcgi_cache_use_stale IA OAAIOAIE.

    *) eO?OA?IAIEA: fastcgi EUU IA EUUEOI?AI IO?AOU, OIOOINYEA OIIOEI EU 
       UACIII?EA.

    *) eO?OA?IAIEA: IUEAEE "select() failed (9: Bad file descriptor)" ? 
       nginx/Unix E "select() failed (10038: ...)" ? nginx/Windows.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE?U debug_connection ? OAAI?AI 
       ?OIAAOOA IIC ?OIEUIEOE segmentation fault; IUEAEA ?IN?EIAOO ? 0.7.54.

    *) eO?OA?IAIEA: ? OAIOEA IIAOIN ngx_http_image_filter_module.

    *) eO?OA?IAIEA: ?AEIU AIIOUA 2G IA ?AOAAA?AIEOO O EO?IIOUI?AIEAI 
       $r->sendfile.
       o?AOEAI iAEOEIO aOIEIO.


eUIAIAIEN ? nginx 0.7.54                                          01.05.2009

    *) aIAA?IAIEA: IIAOIO ngx_http_image_filter_module.

    *) aIAA?IAIEA: AEOAEOE?U proxy_ignore_headers E fastcgi_ignore_headers.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?AOAIAIIUE "open_file_cache_errors 
       on" ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault; IUEAEA 
       ?IN?EIAOO ? 0.7.53.

    *) eO?OA?IAIEA: AEOAEOE?A "port_in_redirect off" IA OAAIOAIA; IUEAEA 
       ?IN?EIAOO ? 0.7.39.

    *) eO?OA?IAIEA: OIO?UAIEA IAOAAIOEE IUEAIE IAOIAA select.

    *) eO?OA?IAIEA: IUEAEE "select() failed (10022: ...)" ? nginx/Windows.

    *) eO?OA?IAIEA: ? OAEOOI?UE OIIAYAIENE IA IUEAEAE ? nginx/Windows; 
       IUEAEA ?IN?EIAOO ? 0.7.53.


eUIAIAIEN ? nginx 0.7.53                                          27.04.2009

    *) eUIAIAIEA: OA?AOO IIC, OEAUAIIUE ? --error-log-path, OIUAA?OON O 
       OAIICI IA?AIA OAAIOU.

    *) aIAA?IAIEA: OA?AOO IUEAEE E ?OAAO?OAOAAIEN ?OE OOAOOA UA?EOU?AAOON ? 
       error_log E ?U?IANOON IA stderr.

    *) aIAA?IAIEA: ?OE OAIOEA O ?OOOUI ?AOAIAOOII --prefix= nginx 
       EO?IIOUOAO EAE ?OA?EEO EAOAIIC, ? EIOIOII II AUI UA?OYAI.

    *) aIAA?IAIEA: EIA? -p.

    *) aIAA?IAIEA: EIA? -s IA Unix-?IAO?IOIAE.

    *) aIAA?IAIEA: EIA?E -? E -h.
       o?AOEAI Jerome Loyet.

    *) aIAA?IAIEA: OA?AOO EIA?E IIOII UAAA?AOO ? OOAOIE ?IOIA.

    *) eO?OA?IAIEA: nginx/Windows IA OAAIOAI, AOIE ?AEI EII?ECOOAAEE AUI 
       UAAAI EIA?II -c.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE? proxy_store, fastcgi_store, 
       proxy_cache EIE fastcgi_cache ?OAIAIIUA ?AEIU IICIE IA OAAINOOON.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ? UACIII?EA Auth-Method UA?OIOA OAO?AOO AOOAIOE?EEAAEE 
       ?I?OI?ICI ?OIEOE-OAO?AOA ?AOAAA?AIIOO IA?AOIIA UIA?AIEA; IUEAEA 
       ?IN?EIAOO ? 0.7.34.
       o?AOEAI Simon Lecaille.

    *) eO?OA?IAIEA: ?OE IICCEOI?AIEE IA Linux IA ?EOAIEOO OAEOOI?UA 
       I?EOAIEN OEOOAIIUE IUEAIE; IUEAEA ?IN?EIAOO ? 0.7.45.

    *) eO?OA?IAIEA: AEOAEOE?A fastcgi_cache_min_uses IA OAAIOAIA.
       o?AOEAI aIAOAA ?IOIAO??O.


eUIAIAIEN ? nginx 0.7.52                                          20.04.2009

    *) aIAA?IAIEA: ?AO?AN AEIAOIAN ?AOOEN ?IA Windows.

    *) eO?OA?IAIEA: EIOOAEOIAN IAOAAIOEA IAOIAA HEAD ?OE EUUEOI?AIEE.

    *) eO?OA?IAIEA: EIOOAEOIAN IAOAAIOEA OOOIE "If-Modified-Since", 
       "If-Range" E EI ?IAIAIUE ? UACIII?EA UA?OIOA EIEAIOA ?OE EUUEOI?AIEE.

    *) eO?OA?IAIEA: OA?AOO OOOIEE "Set-Cookie" E "P3P" OEOU?AAOON ? 
       UACIII?EA IO?AOA AIN UAEUUEOI?AIIUE IO?AOI?.

    *) eO?OA?IAIEA: AOIE nginx AUI OIAOAI O IIAOIAI ngx_http_perl_module E 
       perl ?IAAAOOE?AI ?IOIEE, OI ?OE ?UEIAA IOII?IICI ?OIAAOOA IICIA 
       ?UAA?AOOON IUEAEA "panic: MUTEX_LOCK".

    *) eO?OA?IAIEA: nginx IA OIAEOAION O ?AOAIAOOII --without-http-cache; 
       IUEAEA ?IN?EIAOO ? 0.7.48.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA ?IAO?IOIAE, IOIE?IUE IO i386, 
       amd64, sparc E ppc; IUEAEA ?IN?EIAOO ? 0.7.42.


eUIAIAIEN ? nginx 0.7.51                                          12.04.2009

    *) aIAA?IAIEA: AEOAEOE?A try_files ?IAAAOOE?AAO EIA IO?AOA ? ?IOIAAIAI 
       ?AOAIAOOA.

    *) aIAA?IAIEA: OA?AOO ? AEOAEOE?A return IIOII EO?IIOUI?AOO IAAIE EIA 
       IO?AOA.

    *) eO?OA?IAIEA: AEOAEOE?A error_page AAIAIA ?IAUIEE OAAEOAEO AAU OOOIEE 
       UA?OIOA; IUEAEA ?IN?EIAOO ? 0.7.44.

    *) eO?OA?IAIEA: AOIE OAO?AOA OIOUAIE IA IAOEIIOEEE N?II I?EOAIIUE 
       AAOAOAE, OI ?EOOOAIOIUA OAO?AOA IICIE IA OAAIOAOO; IUEAEA ?IN?EIAOO 
       ? 0.7.39.


eUIAIAIEN ? nginx 0.7.50                                          06.04.2009

    *) eO?OA?IAIEA: ?AOAIAIIUA $arg_... IA OAAIOAIE; IUEAEA ?IN?EIAOO ? 
       0.7.49.


eUIAIAIEN ? nginx 0.7.49                                          06.04.2009

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?AOAIAIIUE $arg_... ? OAAI?AI 
       ?OIAAOOA IIC ?OIEUIEOE segmentation fault; IUEAEA ?IN?EIAOO ? 0.7.48.


eUIAIAIEN ? nginx 0.7.48                                          06.04.2009

    *) aIAA?IAIEA: AEOAEOE?A proxy_cache_key.

    *) eO?OA?IAIEA: OA?AOO nginx O?EOU?AAO ?OE EUUEOI?AIEE OOOIEE 
       "X-Accel-Expires", "Expires" E "Cache-Control" ? UACIII?EA IO?AOA 
       AUEAIAA.

    *) eO?OA?IAIEA: OA?AOO nginx EUUEOOAO OIIOEI IO?AOU IA UA?OIOU GET.

    *) eO?OA?IAIEA: AEOAEOE?A fastcgi_cache_key IA IAOIAAI?AIAOO.

    *) eO?OA?IAIEA: ?AOAIAIIUA $arg_... IA OAAIOAIE O SSI-?IAUA?OIOAIE.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: nginx IA OIAEOAION O AEAIEIOAEIE uclibc.
       o?AOEAI Timothy Redaelli.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA OpenBSD; IUEAEA ?IN?EIAOO 
       ? 0.7.46.


eUIAIAIEN ? nginx 0.7.47                                          01.04.2009

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA FreeBSD 6 E AIIAA OAIIEE ?AOOENE; 
       IUEAEA ?IN?EIAOO ? 0.7.46.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA MacOSX; IUEAEA ?IN?EIAOO ? 0.7.46.

    *) eO?OA?IAIEA: AOIE EO?IIOUI?AION ?AOAIAOO max_size, OI cache manager 
       IIC OAAIEOO ?AOO EUU; IUEAEA ?IN?EIAOO ? 0.7.46.

    *) eUIAIAIEA: ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault, AOIE 
       AEOAEOE?U proxy_cache/fastcgi_cache E proxy_cache_valid/ 
       fastcgi_cache_valid IA AUIE UAAAIU IA IAIII OOI?IA; IUEAEA ?IN?EIAOO 
       ? 0.7.46.

    *) eO?OA?IAIEA: ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault ?OE 
       ?AOAIA?OA?IAIEE UA?OIOA ?OIEOEOI?AIIIIO EIE FastCGI-OAO?AOO O 
       ?IIIYOA error_page EIE try_files; IUEAEA ?IN?EIAOO ? 0.7.44.


eUIAIAIEN ? nginx 0.7.46                                          30.03.2009

    *) eO?OA?IAIEA: AOEE? ?OAAUAOYACI OAIEUA AUI IA?AOIUI.


eUIAIAIEN ? nginx 0.7.45                                          30.03.2009

    *) eUIAIAIEA: OA?AOO AEOAEOE?U proxy_cache E proxy_cache_valid IIOII 
       UAAA?AOO IA OAUIUE OOI?INE.

    *) eUIAIAIEA: ?AOAIAOO clean_time ? AEOAEOE?A proxy_cache_path OAAI?I.

    *) aIAA?IAIEA: ?AOAIAOO max_size ? AEOAEOE?A proxy_cache_path.

    *) aIAA?IAIEA: ?OAA?AOEOAIOIAN ?IAAAOOEA EUUEOI?AIEN ? IIAOIA 
       ngx_http_fastcgi_module.

    *) aIAA?IAIEA: OA?AOO ?OE IUEAEAE ?UAAIAIEN ? OAUAAINAIIE ?AINOE ? IICA 
       OEAUU?AAOON IAU?AIEN AEOAEOE?U E UIIU.

    *) eO?OA?IAIEA: AEOAEOE?A "add_header last-modified ''" IA OAAINIA ? 
       UACIII?EA IO?AOA OOOIEO "Last-Modified"; IUEAEA ?IN?EIAOO ? 0.7.44.

    *) eO?OA?IAIEA: ? AEOAEOE?A auth_basic_user_file IA OAAIOAI 
       IOIIOEOAIOIUE ?OOO, UAAAIIUE OOOIEIE AAU ?AOAIAIIUE; IUEAEA 
       ?IN?EIAOO ? 0.7.44.
       o?AOEAI Jerome Loyet.

    *) eO?OA?IAIEA: ? AEOAEOE?A alias, UAAAIIIE ?AOAIAIIUIE AAU OOUIIE IA 
       ?UAAIAIEN ? OACOINOIUE ?UOAOAIENE; IUEAEA ?IN?EIAOO ? 0.7.42.


eUIAIAIEN ? nginx 0.7.44                                          23.03.2009

    *) aIAA?IAIEA: ?OAA?AOEOAIOIAN ?IAAAOOEA EUUEOI?AIEN ? IIAOIA 
       ngx_http_proxy_module.

    *) aIAA?IAIEA: ?AOAIAOO --with-pcre ? configure.

    *) aIAA?IAIEA: OA?AOO AEOAEOE?A try_files IIOAO AUOO EO?IIOUI?AIA IA 
       OOI?IA server.

    *) eO?OA?IAIEA: AEOAEOE?A try_files IA?OA?EIOII IAOAAAOU?AIA OOOIEO 
       UA?OIOA ? ?IOIAAIAI ?AOAIAOOA.

    *) eO?OA?IAIEA: AEOAEOE?A try_files IICIA IA?AOII OAOOEOI?AOO EAOAIICE.

    *) eO?OA?IAIEA: AOIE AIN ?AOU AAOAO:?IOO I?EOAI OIIOEI IAEI OAO?AO, OI 
       ?UAAIAIEN ? OACOINOIUE ?UOAOAIENE ? AEOAEOE?A server_name IA 
       OAAIOAIE.


eUIAIAIEN ? nginx 0.7.43                                          18.03.2009

    *) eO?OA?IAIEA: UA?OIO IAOAAAOU?AION IA?AOII, AOIE AEOAEOE?A root 
       EO?IIOUI?AIA ?AOAIAIIUA; IUEAEA ?IN?EIAOO ? 0.7.42.

    *) eO?OA?IAIEA: AOIE OAO?AO OIOUAI IA AAOAOAE OE?A "*", OI UIA?AIEA 
       ?AOAIAIIIE $server_addr AUII "0.0.0.0"; IUEAEA ?IN?EIAOO ? 0.7.36.


eUIAIAIEN ? nginx 0.7.42                                          16.03.2009

    *) eUIAIAIEA: IUEAEA "Invalid argument", ?IU?OAYAAIAN 
       setsockopt(TCP_NODELAY) IA Solaris, OA?AOO ECIIOEOOAOON.

    *) eUIAIAIEA: ?OE IOOOOOO?EE ?AEIA, OEAUAIIICI ? AEOAEOE?A 
       auth_basic_user_file, OA?AOO ?IU?OAYAAOON IUEAEA 403 ?IAOOI 500.

    *) aIAA?IAIEA: AEOAEOE?A auth_basic_user_file ?IAAAOOE?AAO ?AOAIAIIUA. 
       o?AOEAI eEOEIIO eIOEIOEIIO.

    *) aIAA?IAIEA: AEOAEOE?A listen ?IAAAOOE?AAO ?AOAIAOO ipv6only.
       o?AOEAI Zhang Hua.

    *) eO?OA?IAIEA: ? AEOAEOE?A alias OI OOUIEAIE IA ?UAAIAIEN ? OACOINOIUE 
       ?UOAOAIENE; IUEAEA ?IN?EIAOO ? 0.7.40.

    *) eO?OA?IAIEA: OI?IAOOEIIOOO O Tru64 UNIX.
       o?AOEAI Dustin Marquess.

    *) eO?OA?IAIEA: nginx IA OIAEOAION AAU AEAIEIOAEE PCRE; IUEAEA 
       ?IN?EIAOO ? 0.7.41.


eUIAIAIEN ? nginx 0.7.41                                          11.03.2009

    *) eO?OA?IAIEA: ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault, 
       AOIE ? server_name EIE location AUIE ?UAAIAIEN ? OACOINOIUE 
       ?UOAOAIENE; IUEAEA ?IN?EIAOO ? 0.7.40.
       o?AOEAI ?IAAEIEOO oI?IOO.


eUIAIAIEN ? nginx 0.7.40                                          09.03.2009

    *) aIAA?IAIEA: AEOAEOE?A location ?IAAAOOE?AAO ?UAAIAIEN ? OACOINOIUE 
       ?UOAOAIENE.

    *) aIAA?IAIEA: AEOAEOE?O alias O OOUIEAIE IA ?UAAIAIEN ? OACOINOIUE 
       ?UOAOAIENE IIOII EO?IIOUI?AOO ?IOOOE location'A, UAAAIIICI 
       OACOINOIUI ?UOAOAIEAI O ?UAAIAIENIE.

    *) aIAA?IAIEA: AEOAEOE?A server_name ?IAAAOOE?AAO ?UAAIAIEN ? 
       OACOINOIUE ?UOAOAIENE.

    *) eUIAIAIEA: IIAOIO ngx_http_autoindex_module IA ?IEAUU?AI ?IOIAAIEE 
       OIUU AIN EAOAIICI? IA ?AEII?IE OEOOAIA XFS; IUEAEA ?IN?EIAOO ? 
       0.7.15.
       o?AOEAI aIEOOEA eOUOIAIEI.


eUIAIAIEN ? nginx 0.7.39                                          02.03.2009

    *) eO?OA?IAIEA: ?OE ?EIA??IIII OOAOEE AIIOUEA IO?AOU O EO?IIOUI?AIEAI 
       SSI IICIE UA?EOAOO; IUEAEA ?IN?EIAOO ? 0.7.28.
       o?AOEAI aOO?IO aIEAIO.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE EIOIOEEE OOAOE?AOEEE ?AOEAIOI? ? 
       AEOAEOE?A try_files ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation 
       fault.


eUIAIAIEN ? nginx 0.7.38                                          23.02.2009

    *) aIAA?IAIEA: IICCEOI?AIEA IUEAIE AOOAIOE?EEAAEE.

    *) eO?OA?IAIEA: EIN/?AOIIO, UAAAIIUA ? auth_basic_user_file, 
       ECIIOEOI?AIEOO ?IOIA IA??OIICI ?EOIA ?OOOUE OOOIE.
       o?AOEAI aIAEOAIAOO uACOAAEIO.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AIEIIICI ?OOE ? unix domain OIEAOA ? 
       CIA?III ?OIAAOOA ?OIEOEIAEI segmentation fault; IUEAEA ?IN?EIAOO ? 
       0.7.36.


eUIAIAIEN ? nginx 0.7.37                                          21.02.2009

    *) eO?OA?IAIEA: AEOAEOE?U, EO?IIOUOAYEA upstream'U, IA OAAIOAIE; IUEAEA 
       ?IN?EIAOO ? 0.7.36.


eUIAIAIEN ? nginx 0.7.36                                          21.02.2009

    *) aIAA?IAIEA: ?OAA?AOEOAIOIAN ?IAAAOOEA IPv6; AEOAEOE?A listen IIAOIN 
       HTTP ?IAAAOOE?AAO IPv6.

    *) eO?OA?IAIEA: ?AOAIAIIAN $ancient_browser IA OAAIOAIA AIN AOAOUAOI?, 
       UAAAIIUE AEOAEOE?AIE modern_browser.


eUIAIAIEN ? nginx 0.7.35                                          16.02.2009

    *) eO?OA?IAIEA: AEOAEOE?A ssl_engine IA EO?IIOUI?AIA SSL-AEOAIAOAOIO 
       AIN AOEIIAOOE?IUE UE?OI?.
       o?AOEAI Marcin Gozdalik.

    *) eO?OA?IAIEA: AEOAEOE?A try_files ?UOOA?INIA MIME-type, EOEIAN EU 
       OAOUEOAIEN ?AO?IIA?AIOIICI UA?OIOA.

    *) eO?OA?IAIEA: ? AEOAEOE?AE server_name, valid_referers E map 
       IA?OA?EIOII IAOAAAOU?AIEOO EIAIA ?EAA "*domain.tld", AOIE 
       EO?IIOUI?AIEOO IAOEE ?EAA ".domain.tld" E ".subdomain.domain.tld"; 
       IUEAEA ?IN?EIAOO ? 0.7.9.


eUIAIAIEN ? nginx 0.7.34                                          10.02.2009

    *) aIAA?IAIEA: ?AOAIAOO off ? AEOAEOE?A if_modified_since.

    *) aIAA?IAIEA: OA?AOO ?IOIA EIIAIAU XCLIENT nginx ?IOUIAAO EIIAIAO 
       HELO/EHLO.
       o?AOEAI iAEOEIO aOIEIO.

    *) aIAA?IAIEA: ?IAAAOOEA Microsoft-O?AAE?E?IICI OAOEIA 
       "AUTH LOGIN with User Name" ? ?I?OI?II ?OIEOE-OAO?AOA.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ? AEOAEOE?A rewrite, ?IU?OAYAAYAE OAAEOAEO, OOAOUA 
       AOCOIAIOU ?OEOIAAEINIEOO E II?UI ?AOAU OEI?II "?" ?IAOOI "&";
       IUEAEA ?IN?EIAOO ? 0.1.18.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA AIX.


eUIAIAIEN ? nginx 0.7.33                                          02.02.2009

    *) eO?OA?IAIEA: AOIE IA UA?OIO O OAIII ?IU?OAYAION OAAEOAEO, OI IO?AO 
       IIC AUOO A?IEIUI ?OE EO?IIOUI?AIEE IAOIAI? epoll EIE rtsig.
       o?AOEAI Eden Li.

    *) eO?OA?IAIEA: AIN IAEIOIOUE OE?I? OAAEOAEOI? ? ?AOAIAIIIE 
       $sent_http_location AUII ?OOOIA UIA?AIEA.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE?U resolver ? SMTP 
       ?OIEOE-OAO?AOA ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault.


eUIAIAIEN ? nginx 0.7.32                                          26.01.2009

    *) aIAA?IAIEA: OA?AOO ? AEOAEOE?A try_files IIOII N?II OEAUAOO ?OI?AOEO 
       EAOAIICA.

    *) eO?OA?IAIEA: fastcgi_store IA ?OACAA OIEOAINI ?AEIU.

    *) eO?OA?IAIEA: ? CAI-AEA?AUIIAE.

    *) eO?OA?IAIEA: IUEAEE ?UAAIAIEN AIIOUEE AIIEI? ? OAUAAINAIIE ?AINOE, 
       AOIE nginx AUI OIAOAI AAU IOIAAEE.
       o?AOEAI aIAOAA e?AOI?O.


eUIAIAIEN ? nginx 0.7.31                                          19.01.2009

    *) eUIAIAIEA: OA?AOO AEOAEOE?A try_files ?OI?AONAO OIIOEI ?AEIU, 
       ECIIOEOON EAOAIICE.

    *) aIAA?IAIEA: AEOAEOE?A fastcgi_split_path_info.

    *) eO?OA?IAIEN ? ?IAAAOOEA OOOIEE "Expect" ? UACIII?EA UA?OIOA.

    *) eO?OA?IAIEN ? CAI-AEA?AUIIAE.

    *) eO?OA?IAIEA: ?OE IOOOOOO?EE IO?AOA ngx_http_memcached_module 
       ?IU?OAYAI ? OAIA IO?AOA OOOIEO "END" ?IAOOI 404-IE OOOAIEAU ?I 
       OIII?AIEA; IUEAEA ?IN?EIAOO ? 0.7.18.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ?OE ?OIEOEOI?AIEE SMPT nginx ?UAA?AI OIIAYAIEA 
       "250 2.0.0 OK" ?IAOOI "235 2.0.0 OK"; IUEAEA ?IN?EIAOO ? 0.7.22.
       o?AOEAI iAEOEIO aOIEIO.


eUIAIAIEN ? nginx 0.7.30                                          24.12.2008

    *) eO?OA?IAIEA: ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation fault, AOIE 
       ? AEOAEOE?AE fastcgi_pass EIE proxy_pass EO?IIOUI?AIEOO ?AOAIAIIUA E 
       EIN EIOOA AIIOII AUII OAUII?EOOON; IUEAEA ?IN?EIAOO ? 0.7.29.


eUIAIAIEN ? nginx 0.7.29                                          24.12.2008

    *) eO?OA?IAIEA: AEOAEOE?U fastcgi_pass E proxy_pass IA ?IAAAOOE?AIE 
       ?AOAIAIIUA ?OE EO?IIOUI?AIEE unix domain OIEAOI?.

    *) eO?OA?IAIEN ? IAOAAIOEA ?IAUA?OIOI?; IUEAEE ?IN?EIEOO ? 0.7.25.

    *) eO?OA?IAIEA: IO?AO "100 Continue" ?UAA?AION AIN UA?OIOI? ?AOOEE 
       HTTP/1.0;
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ? ?UAAIAIEE ?AINOE ? IIAOIA ngx_http_gzip_filter_module 
       ?IA Cygwin.


eUIAIAIEN ? nginx 0.7.28                                          22.12.2008

    *) eUIAIAIEA: ? ?UAAIAIEE ?AINOE ? IIAOIA ngx_http_gzip_filter_module.

    *) eUIAIAIEA: UIA?AIEN ?I OIII?AIEA AIN AEOAEOE?U gzip_buffers EUIAIAIU 
       O 4 4k/8k IA 32 4k EIE 16 8k.


eUIAIAIEN ? nginx 0.7.27                                          15.12.2008

    *) aIAA?IAIEA: AEOAEOE?A try_files.

    *) aIAA?IAIEA: AEOAEOE?A fastcgi_pass ?IAAAOOE?AAO ?AOAIAIIUA.

    *) aIAA?IAIEA: OA?AOO AEOAEOE?A geo IIOAO AOAOO AAOAO EU ?AOAIAIIIE.
       o?AOEAI aIAOAA iECIAOOIEIO.

    *) aIAA?IAIEA: OA?AOO IIAE?EEAOIO location'A IIOII OEAUU?AOO AAU 
       ?OIAAIA ?AOAA IAU?AIEAI.

    *) aIAA?IAIEA: ?AOAIAIIAN $upstream_response_length.

    *) eO?OA?IAIEA: OA?AOO AEOAEOE?A add_header IA AIAA?INAO ?OOOIA 
       UIA?AIEA.

    *) eO?OA?IAIEA: ?OE UA?OIOA ?AEIA IOIA?IE AIEIU nginx UAEOU?AI 
       OIAAEIAIEA, IE?ACI IA ?AOAAA?; IUEAEA ?IN?EIAOO ? 0.7.25.

    *) eO?OA?IAIEA: IAOIA MOVE IA IIC ?AOAIAYAOO ?AEI ? IAOOYAOO?OAYEE 
       EAOAIIC.

    *) eO?OA?IAIEA: AOIE ? OAO?AOA IA AUI I?EOAI IE IAEI EIAII?AIIUE 
       location, II OAEIE location EO?IIOUI?AION ? AEOAEOE?A error_page, OI 
       ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation fault.
       o?AOEAI oAOCAA aI?AIEI?O.


eUIAIAIEN ? nginx 0.7.26                                          08.12.2008

    *) eO?OA?IAIEA: ? IAOAAIOEA ?IAUA?OIOI?; IUEAEA ?IN?EIAOO ? 0.7.25.


eUIAIAIEN ? nginx 0.7.25                                          08.12.2008

    *) eUIAIAIEA: ? IAOAAIOEA ?IAUA?OIOI?.

    *) eUIAIAIEA: OA?AOO OAUOAUAAOON POST'U AAU OOOIEE "Content-Length" ? 
       UACIII?EA UA?OIOA.

    *) eO?OA?IAIEA: OA?AOO AEOAEOE?U limit_req E limit_conn OEAUU?AAO 
       ?OE?EIO UA?OAOA UA?OIOA.

    *) eO?OA?IAIEA: ? ?AOAIAOOA delete AEOAEOE?U geo.


eUIAIAIEN ? nginx 0.7.24                                          01.12.2008

    *) aIAA?IAIEA: AEOAEOE?A if_modified_since.

    *) eO?OA?IAIEA: nginx IA IAOAAAOU?AI IO?AO FastCGI-OAO?AOA, AOIE ?AOAA 
       IO?AOII OAO?AO ?AOAAA?AI IIICI OIIAYAIEE ? stderr.

    *) eO?OA?IAIEA: ?AOAIAIIUA "$cookie_..." IA OAAIOAIE ? SSI and ? 
       ?AOII?II IIAOIA.


eUIAIAIEN ? nginx 0.7.23                                          27.11.2008

    *) aIAA?IAIEA: ?AOAIAOOU delete E ranges ? AEOAEOE?A geo.

    *) aIAA?IAIEA: OOEIOAIEA UACOOUEE geo-AAUU O AIIOUEI ?EOIII UIA?AIEE.

    *) aIAA?IAIEA: OIAIOUAIEA ?AINOE, IAIAEIAEIIE AIN UACOOUEE geo-AAUU.


eUIAIAIEN ? nginx 0.7.22                                          20.11.2008

    *) aIAA?IAIEA: ?AOAIAOO none ? AEOAEOE?A smtp_auth.
       o?AOEAI iAEOEIO aOIEIO.

    *) aIAA?IAIEA: ?AOAIAIIUA "$cookie_...".

    *) eO?OA?IAIEA: AEOAEOE?A directio IA OAAIOAIA O ?AEII?IE OEOOAIIE XFS.

    *) eO?OA?IAIEA: resolver IA ?IIEIAI AIIOUEA DNS-IO?AOU.
       o?AOEAI Zyb.


eUIAIAIEN ? nginx 0.7.21                                          11.11.2008

    *) eUIAIAIEN ? IIAOIA ngx_http_limit_req_module.

    *) aIAA?IAIEA: ?IAAAOOEA EXSLT ? IIAOIA ngx_http_xslt_module.
       o?AOEAI aAIEOO iAOU?I?O.

    *) eUIAIAIEA: OI?IAOOEIIOOO O glibc 2.3.
       o?AOEAI Eric Benson E iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: nginx IA UA?OOEAION IA MacOSX 10.4 E AIIAA OAIIEE; 
       IUEAEA ?IN?EIAOO ? 0.7.6.


eUIAIAIEN ? nginx 0.7.20                                          10.11.2008

    *) eUIAIAIEN ? IIAOIA ngx_http_gzip_filter_module.

    *) aIAA?IAIEA: IIAOIO ngx_http_limit_req_module.

    *) eO?OA?IAIEA: IA ?IAO?IOIAE sparc E ppc OAAI?EA ?OIAAOOU IICIE 
       ?UEIAEOO ?I OECIAIO SIGBUS; IUEAEA ?IN?EIAOO ? 0.7.3.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: AEOAEOE?U ?EAA "proxy_pass http://host/some:uri" IA 
       OAAIOAIE; IUEAEA ?IN?EIAOO ? 0.7.12.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE HTTPS UA?OIOU IICIE UA?AOUAOOON O 
       IUEAEIE "bad write retry".

    *) eO?OA?IAIEA: IIAOIO ngx_http_secure_link_module IA OAAIOAI ?IOOOE 
       location'I? O EIAIAIE IAIOUA 3 OEI?III?.

    *) eO?OA?IAIEA: ?AOAIAIIAN $server_addr IICIA IA EIAOO UIA?AIEN.


eUIAIAIEN ? nginx 0.7.19                                          13.10.2008

    *) eO?OA?IAIEA: IAII?IAIEA IIIAOA ?AOOEE.


eUIAIAIEN ? nginx 0.7.18                                          13.10.2008

    *) eUIAIAIEA: AEOAEOE?A underscores_in_headers; OA?AOO nginx ?I 
       OIII?AIEA IA OAUOAUAAO ?IA??OEE?AIEN ? EIAIAE OOOIE ? UACIII?EA 
       UA?OIOA EIEAIOA.

    *) aIAA?IAIEA: IIAOIO ngx_http_secure_link_module.

    *) aIAA?IAIEA: AEOAEOE?A real_ip_header ?IAAAOOE?AAO IAAIE UACIII?IE.

    *) aIAA?IAIEA: AEOAEOE?A log_subrequest.

    *) aIAA?IAIEA: ?AOAIAIIAN $realpath_root.

    *) aIAA?IAIEA: ?AOAIAOOU http_502 E http_504 ? AEOAEOE?A 
       proxy_next_upstream.

    *) eO?OA?IAIEA: ?AOAIAOO http_503 ? AEOAEOE?AE proxy_next_upstream EIE 
       fastcgi_next_upstream IA OAAIOAI.

    *) eO?OA?IAIEA: nginx IIC ?UAA?AOO OOOIEO "Transfer-Encoding: chunked" 
       AIN UA?OIOI? HEAD.

    *) eO?OA?IAIEA: OA?AOO accept-IEIEO UA?EOEO IO ?EOIA worker_connections.


eUIAIAIEN ? nginx 0.7.17                                          15.09.2008

    *) aIAA?IAIEA: AEOAEOE?A directio OA?AOO OAAIOAAO IA Linux.

    *) aIAA?IAIEA: ?AOAIAIIAN $pid.

    *) eO?OA?IAIEA: I?OEIEUAAEN directio, ?IN?E?UANON ? 0.7.15, IA OAAIOAIA 
       ?OE EO?IIOUI?AIEE open_file_cache.

    *) eO?OA?IAIEA: access_log O ?AOAIAIIUIE IA OAAIOAI IA Linux; IUEAEA 
       ?IN?EIAOO ? 0.7.7.

    *) eO?OA?IAIEA: IIAOIO ngx_http_charset_module IA ?IIEIAI IAU?AIEA 
       EIAEOI?EE ? EA?U?EAE, ?IIO?AIIIA IO AUEAIAA.


eUIAIAIEN ? nginx 0.7.16                                          08.09.2008

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA 64-AEOIUE ?IAO?IOIAE; IUEAEA 
       ?IN?EIAOO ? 0.7.15.


eUIAIAIEN ? nginx 0.7.15                                          08.09.2008

    *) aIAA?IAIEA: IIAOIO ngx_http_random_index_module.

    *) aIAA?IAIEA: AEOAEOE?A directio I?OEIEUEOI?AIA AIN UA?OIOI? ?AEII?, 
       IA?EIAAYEEON O ?OIEU?IIOIIE ?IUEAEE.

    *) aIAA?IAIEA: AEOAEOE?A directio ?OE IAIAEIAEIIOOE UA?OAYAAO 
       EO?IIOUI?AIEA sendfile.

    *) aIAA?IAIEA: OA?AOO nginx OAUOAUAAO ?IA??OEE?AIEN ? EIAIAE OOOIE ? 
       UACIII?EA UA?OIOA EIEAIOA.


eUIAIAIEN ? nginx 0.7.14                                          01.09.2008

    *) eUIAIAIEA: OA?AOO AEOAEOE?U ssl_certificate E ssl_certificate_key IA 
       EIAAO UIA?AIEE ?I OIII?AIEA.

    *) aIAA?IAIEA: AEOAEOE?A listen ?IAAAOOE?AAO ?AOAIAOO ssl.

    *) aIAA?IAIEA: OA?AOO ?OE ?AOAEII?ECOOAAEE nginx O?EOU?AAO EUIAIAIEA 
       ?OAIAIIIE UIIU IA FreeBSD E Linux.

    *) eO?OA?IAIEA: ?AOAIAOOU AEOAEOE?U listen, OAEEA EAE backlog, rcvbuf E 
       ?OI?EA, IA OOOAIA?IE?AIEOO, AOIE OAO?AOII ?I OIII?AIEA AUI IA ?AO?UE 
       OAO?AO.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ? EA?AOO?A AOCOIAIOI? ?AOOE URI, 
       ?UAAIAIIICI O ?IIIYOA AEOAEOE?U rewrite, UOE AOCOIAIOU IA 
       UEOAIEOI?AIEOO.

    *) eO?OA?IAIEA: OIO?UAIEN OAOOEOI?AIEN ?OA?EIOIIOOE EII?ECOOAAEIIIICI 
       ?AEIA.


eUIAIAIEN ? nginx 0.7.13                                          26.08.2008

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA Linux E Solaris; IUEAEA ?IN?EIAOO 
       ? 0.7.12.


eUIAIAIEN ? nginx 0.7.12                                          26.08.2008

    *) aIAA?IAIEA: AEOAEOE?A server_name ?IAAAOOE?AAO ?OOOIA EIN "".

    *) aIAA?IAIEA: AEOAEOE?A gzip_disable ?IAAAOOE?AAO O?AAEAIOIOA IAOEO 
       msie6.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?AOAIAOOA max_fails=0 ? upstream'A O 
       IAOEIIOEEIE OAO?AOAIE OAAI?EE ?OIAAOO ?UEIAEI ?I OECIAIO SIGFPE.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: ?OE ?AOAIA?OA?IAIEE UA?OIOA O ?IIIYOA AEOAEOE?U 
       error_page OAONIIOO OAII UA?OIOA.

    *) eO?OA?IAIEA: ?OE ?AOAIA?OA?IAIEE UA?OIOA O IAOIAII HEAD O ?IIIYOA 
       AEOAEOE?U error_page ?IU?OAYAION ?IIIUE IO?AO.

    *) eO?OA?IAIEA: IAOIA $r->header_in() IA ?IU?OAYAI UIA?AIEN OOOIE 
       "Host", "User-Agent", E "Connection" EU UACIII?EA UA?OIOA; IUEAEA 
       ?IN?EIAOO ? 0.7.0.


eUIAIAIEN ? nginx 0.7.11                                          18.08.2008

    *) eUIAIAIEA: OA?AOO ngx_http_charset_module ?I OIII?AIEA IA OAAIOAAO 
       MIME-OE?II text/css.

    *) aIAA?IAIEA: OA?AOO nginx ?IU?OAYAAO EIA 405 AIN IAOIAA POST ?OE 
       UA?OIOA OOAOE?AOEICI ?AEIA, OIIOEI AOIE ?AEI OOYAOO?OAO.

    *) aIAA?IAIEA: AEOAEOE?A proxy_ssl_session_reuse.

    *) eO?OA?IAIEA: ?IOIA ?AOAIA?OA?IAIEN UA?OIOA O ?IIIYOA 
       "X-Accel-Redirect" AEOAEOE?A proxy_pass AAU URI IICIA EO?IIOUI?AOO 
       IOECEIAIOIUE UA?OIO.

    *) eO?OA?IAIEA: AOIE O EAOAIICA AUIE ?OA?A AIOOO?A OIIOEI IA ?IEOE 
       ?AEII? E ?AO?UE EIAAEOIUE ?AEI IOOOOOO?I?AI, OI nginx ?IU?OAYAI 
       IUEAEO 500.

    *) eO?OA?IAIEA: IUEAIE ?I ?IIOAIIUE location'AE; IUEAEE ?IN?EIEOO ? 
       0.7.1.


eUIAIAIEN ? nginx 0.7.10                                          13.08.2008

    *) eO?OA?IAIEA: IUEAIE ? AEOAEOE?AE addition_types, charset_types, 
       gzip_types, ssi_types, sub_filter_types E xslt_types; IUEAEE 
       ?IN?EIEOO ? 0.7.9.

    *) eO?OA?IAIEA: OAEOOOE?IIE error_page AIN 500 IUEAEE.

    *) eO?OA?IAIEA: OA?AOO IIAOIO ngx_http_realip_module OOOAIA?IE?AAO 
       AAOAO IA AIN ?OACI keepalive OIAAEIAIEN, A AIN EAOAICI UA?OIOA ?I 
       UOIIO OIAAEIAIEA.


eUIAIAIEN ? nginx 0.7.9                                           12.08.2008

    *) eUIAIAIEA: OA?AOO ngx_http_charset_module ?I OIII?AIEA OAAIOAAO OI 
       OIAAOAYEIE MIME-OE?AIE: text/html, text/css, text/xml, text/plain, 
       text/vnd.wap.wml, application/x-javascript E application/rss+xml.

    *) aIAA?IAIEA: AEOAEOE?U charset_types E addition_types.

    *) aIAA?IAIEA: OA?AOO AEOAEOE?U gzip_types, ssi_types E 
       sub_filter_types EO?IIOUOAO EUU.

    *) aIAA?IAIEA: IIAOIO ngx_cpp_test_module.

    *) aIAA?IAIEA: AEOAEOE?A expires ?IAAAOOE?AAO OOOI?IIA ?OAIN.

    *) aIAA?IAIEA: OIO?UAIEN E EO?OA?IAIEN ? IIAOIA 
       ngx_http_xslt_module.
       o?AOEAI aAIEOO iAOU?I?O E iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: AEOAEOE?A log_not_found IA OAAIOAIA ?OE ?IEOEA 
       EIAAEOIUE ?AEII?.

    *) eO?OA?IAIEA: HTTPS-OIAAEIAIEN IICIE UA?EOIOOO, AOIE EO?IIOUI?AIEOO 
       IAOIAU kqueue, epoll, rtsig EIE eventport; IUEAEA ?IN?EIAOO ? 0.7.7.

    *) eO?OA?IAIEA: AOIE ? AEOAEOE?AE server_name, valid_referers E map 
       EO?IIOUI?AIAOO IAOEA ?EAA "*.domain.tld" E ?OE UOII ?IIIIA EIN ?EAA 
       "domain.tld" IA AUII I?EOAII, OI UOI EIN ?I?AAAII ?IA IAOEO; IUEAEA 
       ?IN?EIAOO ? 0.3.18.


eUIAIAIEN ? nginx 0.7.8                                           04.08.2008

    *) aIAA?IAIEA: IIAOIO ngx_http_xslt_module.

    *) aIAA?IAIEA: ?AOAIAIIUA "$arg_...".

    *) aIAA?IAIEA: ?IAAAOOEA directio ? Solaris.
       o?AOEAI Ivan Debnar.

    *) eO?OA?IAIEA: OA?AOO, AOIE FastCGI-OAO?AO ?OEOUIAAO OOOIEO "Location" 
       ? UACIII?EA IO?AOA AAU OOOIEE OOAOOOA, OI nginx EO?IIOUOAO EIA 
       OOAOOOA 302.
       o?AOEAI iAEOEIO aOIEIO.


eUIAIAIEN ? nginx 0.7.7                                           30.07.2008

    *) eUIAIAIEA: OA?AOO IUEAEA EAGAIN ?OE ?UUI?A connect() IA O?EOAAOON 
       ?OAIAIIIE.

    *) eUIAIAIEA: UIA?AIEAI ?AOAIAIIIE $ssl_client_cert OA?AOO N?INAOON 
       OAOOE?EEAO, ?AOAA EAOAIE OOOIEIE EIOIOICI, EOIIA ?AO?IE, ?OOA?INAOON 
       OEI?II OAAOINAEE; IAEUIAI?IIUE OAOOE?EEAO AIOOO?AI ?AOAU ?AOAIAIIOA 
       $ssl_client_raw_cert.

    *) aIAA?IAIEA: ?AOAIAOO ask AEOAEOE?U ssl_verify_client.

    *) aIAA?IAIEA: OIO?UAIEN ? IAOAAIOEA byte-range.
       o?AOEAI iAEOEIO aOIEIO.

    *) aIAA?IAIEA: AEOAEOE?A directio.
       o?AOEAI Jiang Hong.

    *) aIAA?IAIEA: ?IAAAOOEA sendfile() ? MacOSX 10.5.

    *) eO?OA?IAIEA: ? MacOSX E Cygwin ?OE ?OI?AOEA location'I? OA?AOO 
       AAIAAOON OOA?IAIEA AAU O??OA OACEOOOA OEI?III?; IAIAEI, OOA?IAIEA 
       ICOAIE?AII OIIOEI IAIIAAEOIUIE locale'NIE.

    *) eO?OA?IAIEA: OIAAEIAIEN ?I?OI?ICI ?OIEOE-OAO?AOA UA?EOAIE ? OAOEIA 
       SSL, AOIE EO?IIOUI?AIEOO IAOIAU select, poll EIE /dev/poll.

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE EIAEOI?EE UTF-8 ? 
       ngx_http_autoindex_module.


eUIAIAIEN ? nginx 0.7.6                                           07.07.2008

    *) eO?OA?IAIEA: OA?AOO ?OE EO?IIOUI?AIEE ?AOAIAIIUE ? AEOAEOE?A 
       access_log ?OACAA ?OI?AONAOON OOYAOO?I?AIEE root'A AIN UA?OIOA.

    *) eO?OA?IAIEA: IIAOIO ngx_http_flv_module IA ?IAAAOOE?AI IAOEIIOEI 
       UIA?AIEE ? AOCOIAIOAE UA?OIOA.


eUIAIAIEN ? nginx 0.7.5                                           01.07.2008

    *) eO?OA?IAIEN ? ?IAAAOOEA ?AOAIAIIUE ? AEOAEOE?A access_log; IUEAEE 
       ?IN?EIEOO ? 0.7.4.

    *) eO?OA?IAIEA: nginx IA OIAEOAION O ?AOAIAOOII 
       --without-http_gzip_module; IUEAEA ?IN?EIAOO ? 0.7.3.
       o?AOEAI eEOEIIO eIOEIOEIIO.

    *) eO?OA?IAIEA: ?OE OI?IAOOIII EO?IIOUI?AIEE sub_filter E SSI IO?AOU 
       IICIE ?AOAAA?AOOON IA?AOII.


eUIAIAIEN ? nginx 0.7.4                                           30.06.2008

    *) aIAA?IAIEA: AEOAEOE?A access_log ?IAAAOOE?AAO ?AOAIAIIUA.

    *) aIAA?IAIEA: AEOAEOE?A open_log_file_cache.

    *) aIAA?IAIEA: EIA? -g.

    *) aIAA?IAIEA: ?IAAAOOEA OOOIEE "Expect" ? UACIII?EA UA?OIOA.

    *) eO?OA?IAIEA: AIIOUEA ?EIA?AIEN ? SSI IICIE ?AOAAA?AIEOO IA ?IIIIOOOA.


eUIAIAIEN ? nginx 0.7.3                                           23.06.2008

    *) eUIAIAIEA: MIME-OE? AIN OAOUEOAIEN rss EUIAI?I IA 
       "application/rss+xml".

    *) eUIAIAIEA: OA?AOO AEOAEOE?A "gzip_vary on" ?UAA?O OOOIEO 
       "Vary: Accept-Encoding" ? UACIII?EA IO?AOA E AIN IAOOAOUE IO?AOI?.

    *) aIAA?IAIEA: OA?AOO ?OE EO?IIOUI?AIEE ?OIOIEIIA "https://" ? 
       AEOAEOE?A rewrite A?OIIAOE?AOEE AAIAAOON OAAEOAEO.

    *) eO?OA?IAIEA: AEOAEOE?A proxy_pass IA OAAIOAIA O ?OIOIEIIII HTTPS; 
       IUEAEA ?IN?EIAOO ? 0.6.9.


eUIAIAIEN ? nginx 0.7.2                                           16.06.2008

    *) aIAA?IAIEA: OA?AOO nginx ?IAAAOOE?AAO UE?OU O IAIAIII EDH-EIA?AIE.

    *) aIAA?IAIEA: AEOAEOE?A ssl_dhparam.

    *) aIAA?IAIEA: ?AOAIAIIAN $ssl_client_cert.
       o?AOEAI Manlio Perillo.

    *) eO?OA?IAIEA: ?IOIA EUIAIAIEN URI O ?IIIYOA AEOAEOE?U rewrite nginx 
       IA EOEAI II?UE location; IUEAEA ?IN?EIAOO ? 0.7.1.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: nginx IA OIAEOAION AAU AEAIEIOAEE PCRE; IUEAEA 
       ?IN?EIAOO ? 0.7.1.

    *) eO?OA?IAIEA: ?OE OAAEOAEOA UA?OIOA E EAOAIICO O AIAA?IAIEAI OIUUA 
       nginx IA AIAA?INI AOCOIAIOU EU IOECEIAIOIICI UA?OIOA.


eUIAIAIEN ? nginx 0.7.1                                           26.05.2008

    *) eUIAIAIEA: OA?AOO ?IEOE location'A AAIAAOON O ?IIIYOA AAOA?A.

    *) eUIAIAIEA: AEOAEOE?A optimize_server_names O?OAUAIAIA ? O?NUE O 
       ?IN?IAIEAI AEOAEOE?U server_name_in_redirect.

    *) eUIAIAIEA: IAEIOIOUA AA?II OOOAOA?UEA AEOAEOE?U AIIOUA IA 
       ?IAAAOOE?AAOON.

    *) eUIAIAIEA: ?AOAIAOO "none" ? AEOAEOE?A ssl_session_cache; OA?AOO 
       UOIO ?AOAIAOO EO?IIOUOAOON ?I OIII?AIEA.
       o?AOEAI Rob Mueller.

    *) eO?OA?IAIEA: OAAI?EA ?OIAAOOU IICIE IA OAACEOI?AOO IA OECIAIU 
       ?AOAEII?ECOOAAEE E OIOAAEE IICI?.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA ?IOIAAIEE Fedora 9 Linux.
       o?AOEAI Roxis.


eUIAIAIEN ? nginx 0.7.0                                           19.05.2008

    *) eUIAIAIEA: OA?AOO OEI?IIU 0x00-0x1F, '"' E '\' ? access_log 
       UA?EOU?AAOON ? ?EAA \xXX.
       o?AOEAI iAEOEIO aOIEIO.

    *) eUIAIAIEA: OA?AOO nginx OAUOAUAAO IAOEIIOEI OOOIE "Host" ? UACIII?EA 
       UA?OIOA.

    *) aIAA?IAIEA: AEOAEOE?A expires ?IAAAOOE?AAO ?IAC modified.

    *) aIAA?IAIEA: ?AOAIAIIUA $uid_got E $uid_set IIOII EO?IIOUI?AOO IA 
       IAAIE OOAAEE IAOAAIOEE UA?OIOA.

    *) aIAA?IAIEA: ?AOAIAIIAN $hostname.
       o?AOEAI aIAOAA iECIAOOIEIO.

    *) aIAA?IAIEA: ?IAAAOOEA DESTDIR.
       o?AOEAI Todd A. Fisher E Andras Voroskoi.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE keepalive IA Linux ? OAAI?AI ?OIAAOOA 
       IIC ?OIEUIEOE segmentation fault.


eUIAIAIEN ? nginx 0.6.31                                          12.05.2008

    *) eO?OA?IAIEA: nginx IA IAOAAAOU?AI IO?AO FastCGI-OAO?AOA, AOIE OOOIEA 
       UACIII?EA IO?AO AUIA ? EIIAA UA?EOE FastCGI; IUEAEA ?IN?EIAOO ? 
       0.6.2.
       o?AOEAI oAOCAA oAOI?O.

    *) eO?OA?IAIEA: ?OE OAAIAIEE ?AEIA E EO?IIOUI?AIEE AEOAEOE?U 
       open_file_cache_errors off ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE 
       segmentation fault.


eUIAIAIEN ? nginx 0.6.30                                          29.04.2008

    *) eUIAIAIEA: OA?AOO, AOIE IAOEA, UAAAIIIE ? AEOAEOE?A include, IA 
       OIIO?AOOO?OAO IE IAEI ?AEI, OI nginx IA ?UAA?O IUEAEO.

    *) aIAA?IAIEA: OA?AOO ?OAIN ? AEOAEOE?AE IIOII UAAA?AOO AAU ?OIAAIA, 
       IA?OEIAO, "1h50m".

    *) eO?OA?IAIEA: OOA?AE ?AINOE, AOIE AEOAEOE?A ssl_verify_client EIAIA 
       UIA?AIEA on.
       o?AOEAI Chavelle Vincent.

    *) eO?OA?IAIEA: AEOAEOE?A sub_filter IICIA ?OOA?INOO UAIAINAIUE OAEOO ? 
       ?U?IA.

    *) eO?OA?IAIEA: AEOAEOE?A error_page IA ?IO?OEIEIAIA ?AOAIAOOU ? 
       ?AOAIA?OA?INAIII URI.

    *) eO?OA?IAIEA: OA?AOO ?OE OAIOEA O Cygwin nginx ?OACAA IOEOU?AAO ?AEIU 
       ? AEIAOIII OAOEIA.

    *) eO?OA?IAIEA: nginx IA OIAEOAION ?IA OpenBSD; IUEAEA ?IN?EIAOO ? 
       0.6.15.


eUIAIAIEN ? nginx 0.6.29                                          18.03.2008

    *) aIAA?IAIEA: IIAOIO ngx_google_perftools_module.

    *) eO?OA?IAIEA: IIAOIO ngx_http_perl_module IA OIAEOAION IA 64-AEOIUE 
       ?IAO?IOIAE; IUEAEA ?IN?EIAOO ? 0.6.27.


eUIAIAIEN ? nginx 0.6.28                                          13.03.2008

    *) eO?OA?IAIEA: IAOIA rtsig IA OIAEOAION; IUEAEA ?IN?EIAOO ? 0.6.27.


eUIAIAIEN ? nginx 0.6.27                                          12.03.2008

    *) eUIAIAIEA: OA?AOO IA Linux 2.6.18+ ?I OIII?AIEA IA OIAEOAAOON IAOIA 
       rtsig.

    *) eUIAIAIEA: OA?AOO ?OE ?AOAIA?OA?IAIEE UA?OIOA ? EIAII?AIIUE location 
       O ?IIIYOA AEOAEOE?U error_page IAOIA UA?OIOA IA EUIAINAOON.

    *) aIAA?IAIEA: AEOAEOE?U resolver E resolver_timeout ? SMTP 
       ?OIEOE-OAO?AOA.

    *) aIAA?IAIEA: AEOAEOE?A post_action ?IAAAOOE?AAO EIAII?AIIUA 
       location'U.

    *) eO?OA?IAIEA: ?OE ?AOAIA?OA?IAIEE UA?OIOA EU location'A c 
       IAOAAIO?EEII proxy, FastCGI EIE memcached ? EIAII?AIIUE location OI 
       OOAOE?AOEEI IAOAAIO?EEII ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation 
       fault.

    *) eO?OA?IAIEA: AOAOUAOU IA ?I?OIONIE SSL handshake, AOIE ?OE ?AO?II 
       handshake IA IEAUAIIOO ?OA?EIOIICI EIEAIOOEICI OAOOE?EEAOA. 
       o?AOEAI aIAEOAIAOO eIAEEIO.

    *) eO?OA?IAIEA: ?OE ?AOAIA?OA?IAIEE IUEAIE 495-497 O ?IIIYOA AEOAEOE?U 
       error_page AAU EUIAIAIEN EIAA IUEAEE nginx ?UOAION ?UAAIEOO I?AIO 
       IIICI ?AINOE.

    *) eO?OA?IAIEA: OOA?EE ?AINOE ? AIICIOE?OYEE IAAO??AOEUEOI?AIIUE 
       OIAAEIAIENE.

    *) eO?OA?IAIEA: OOA?EE ?AINOE ? resolver'A.

    *) eO?OA?IAIEA: ?OE ?AOAIA?OA?IAIEE UA?OIOA EU location'A c 
       IAOAAIO?EEII proxy ? AOOCIE location O IAOAAIO?EEII proxy ? OAAI?AI 
       ?OIAAOOA ?OIEOEIAEI segmentation fault.

    *) eO?OA?IAIEA: IUEAEE ? EUUEOI?AIEE ?AOAIAIIUE $proxy_host E 
       $proxy_port.
       o?AOEAI oAOCAA aI?AIEI?O.

    *) eO?OA?IAIEA: AEOAEOE?A proxy_pass O ?AOAIAIIUIE EO?IIOUI?AIA ?IOO, 
       I?EOAIIIE ? AOOCIE AEOAEOE?A proxy_pass AAU ?AOAIAIIUE, II O OAEEI 
       OA EIAIAI EIOOA.
       o?AOEAI oAOCAA aI?AIEI?O.

    *) eO?OA?IAIEA: ?I ?OAIN ?AOAEII?ECOOAAEE IA IAEIOIOUE 64-AEOIII 
       ?IAO?IOIAE ? IIC UA?EOU?AION alert "sendmsg() failed (9: Bad file 
       descriptor)".

    *) eO?OA?IAIEA: ?OE ?I?OIOIII EO?IIOUI?AIEE ? SSI ?OOOICI block'A ? 
       EA?AOO?A UACIOUEE ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation fault.

    *) eO?OA?IAIEA: IUEAEE ?OE EI?EOI?AIEE ?AOOE URI, OIAAOOAYACI 
       UEOAIEOI?AIIUA OEI?IIU, ? AOCOIAIOU.


eUIAIAIEN ? nginx 0.6.26                                          11.02.2008

    *) eO?OA?IAIEA: AEOAEOE?U proxy_store E fastcgi_store IA ?OI?AONIE 
       AIEIO IO?AOA.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AIIOUICI UIA?AIEN ? AEOAEOE?A expires 
       ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation fault.
       o?AOEAI Joaquin Cuenca Abela.

    *) eO?OA?IAIEA: nginx IA?AOII I?OAAAINI AIEIO OOOIEE EUUA IA 
       Pentium 4.
       o?AOEAI cAIIAAEA iAEIIAAO.

    *) eO?OA?IAIEA: ? ?OIEOEOI?AIIUE ?IAUA?OIOAE E ?IAUA?OIOAE E 
       FastCGI-OAO?AOO ?IAOOI IAOIAA GET EO?IIOUI?AION IOECEIAIOIUE IAOIA 
       EIEAIOA.

    *) eO?OA?IAIEA: OOA?EE OIEAOI? ? OAOEIA HTTPS ?OE EO?IIOUI?AIEE 
       IOIIOAIIICI accept'A.
       o?AOEAI Ben Maurer.

    *) eO?OA?IAIEA: nginx ?UAA?AI IUEAI?IIA OIIAYAIEA "SSL_shutdown() 
       failed (SSL: )"; IUEAEA ?IN?EIAOO ? 0.6.23.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE HTTPS UA?OIOU IICIE UA?AOUAOOON O 
       IUEAEIE "bad write retry"; IUEAEA ?IN?EIAOO ? 0.6.23.


eUIAIAIEN ? nginx 0.6.25                                          08.01.2008

    *) eUIAIAIEA: ?IAOOI O?AAEAIOIICI ?AOAIAOOA "*" ? AEOAEOE?A server_name 
       OA?AOO EO?IIOUOAOON AEOAEOE?A server_name_in_redirect.

    *) eUIAIAIEA: ? EA?AOO?A IOII?IICI EIAIE ? AEOAEOE?A server_name OA?AOO 
       IIOII EO?IIOUI?AOO EIAIA O IAOEAIE E OACOINOIUIE ?UOAOAIENIE.

    *) eUIAIAIEA: AEOAEOE?A satisfy_any UAIAIAIA AEOAEOE?IE satisfy.

    *) eUIAIAIEA: ?IOIA ?AOAEII?ECOOAAEE OOAOUA OAAI?EA ?OIAAOO IICIE 
       OEIOII IACOOOAOO ?OIAAOOIO ?OE UA?OOEA ?IA Linux OpenVZ.

    *) aIAA?IAIEA: AEOAEOE?A min_delete_depth.

    *) eO?OA?IAIEA: IAOIAU COPY E MOVE IA OAAIOAIE O IAEII?IUIE ?AEIAIE.

    *) eO?OA?IAIEA: IIAOIO ngx_http_gzip_static_module IA ?IU?IINI OAAIOAOO 
       IIAOIA ngx_http_dav_module; IUEAEA ?IN?EIAOO ? 0.6.23.

    *) eO?OA?IAIEA: OOA?EE OIEAOI? ? OAOEIA HTTPS ?OE EO?IIOUI?AIEE 
       IOIIOAIIICI accept'A.
       o?AOEAI Ben Maurer.

    *) eO?OA?IAIEA: nginx IA OIAEOAION AAU AEAIEIOAEE PCRE; IUEAEA 
       ?IN?EIAOO ? 0.6.23.


eUIAIAIEN ? nginx 0.6.24                                          27.12.2007

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE HTTPS ? OAAI?AI ?OIAAOOA IIC 
       ?OIEUIEOE segmentation fault; IUEAEA ?IN?EIAOO ? 0.6.23.


eUIAIAIEN ? nginx 0.6.23                                          27.12.2007

    *) eUIAIAIEA: ?AOAIAOO "off" ? AEOAEOE?A ssl_session_cache; OA?AOO UOIO 
       ?AOAIAOO EO?IIOUOAOON ?I OIII?AIEA.

    *) eUIAIAIEA: AEOAEOE?A open_file_cache_retest ?AOAEIAII?AIA ? 
       open_file_cache_valid.

    *) aIAA?IAIEA: AEOAEOE?A open_file_cache_min_uses.

    *) aIAA?IAIEA: IIAOIO ngx_http_gzip_static_module.

    *) aIAA?IAIEA: AEOAEOE?A gzip_disable.

    *) aIAA?IAIEA: AEOAEOE?O memcached_pass IIOII EO?IIOUI?AOO ?IOOOE AIIEA 
       if.

    *) eO?OA?IAIEA: AOIE ?IOOOE IAIICI location'A EO?IIOUI?AIEOO AEOAEOE?U 
       "memcached_pass" E "if", OI ? OAAI?AI ?OIAAOOA ?OIEOEIAEI 
       segmentation fault.

    *) eO?OA?IAIEA: AOIE ?OE EO?IIOUI?AIEE AEOAEOE?U satisfy_any on" AUIE 
       UAAAIU AEOAEOE?U IA ?OAE IIAOIAE AIOOO?A, OI UAAAIIUA AEOAEOE?U IA 
       ?OI?AONIEOO.

    *) eO?OA?IAIEA: ?AOAIAOOU, UAAAIIUA OACOINOIUI ?UOAOAIEAI ? AEOAEOE?A 
       valid_referers, IA IAOIAAI?AIAOO O ?OAAUAOYACI OOI?IN.

    *) eO?OA?IAIEA: AEOAEOE?A post_action IA OAAIOAIA, AOIE UA?OIO 
       UA?AOUAION O EIAII 499.

    *) eO?OA?IAIEA: I?OEIEUAAEN EO?IIOUI?AIEN 16K AO?AOA AIN 
       SSL-OIAAEIAIEN.
       o?AOEAI Ben Maurer.

    *) eO?OA?IAIEA: STARTTLS ? OAOEIA SMTP IA OAAIOAI.
       o?AOEAI iIACO iIOEAIEI.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE HTTPS UA?OIOU IICIE UA?AOUAOOON O 
       IUEAEIE "bad write retry"; IUEAEA ?IN?EIAOO ? 0.5.13.


eUIAIAIEN ? nginx 0.6.22                                          19.12.2007

    *) eUIAIAIEA: OA?AOO ?OA IAOIAU IIAOIN ngx_http_perl_module ?IU?OAYAAO 
       UIA?AIEN, OEI?EOI?AIIUA ? ?AINOO, ?UAAIAIIOA perl'II.

    *) eO?OA?IAIEA: AOIE nginx AUI OIAOAI O IIAOIAI ngx_http_perl_module, 
       EO?IIOUI?AION perl AI ?AOOEE 5.8.6 E perl ?IAAAOOE?AI ?IOIEE, OI ?I 
       ?OAIN ?AOAEII?ECOOAAEE IOII?IIE ?OIAAOO A?AOEEII ?UEIAEI; IUEAEA 
       ?IN?EIAOO ? 0.5.9.
       o?AOEAI aIOEOO oIOOI?O.

    *) eO?OA?IAIEA: ? IAOIAU IIAOIN ngx_http_perl_module IICIE ?AOAAA?AOOON 
       IA?AOIUA OAUOIOOAOU ?UAAIAIEN ? OACOINOIUE ?UOAOAIENE.

    *) eO?OA?IAIEA: AOIE IAOIA $r->has_request_body() ?UUU?AION AIN 
       UA?OIOA, O EIOIOICI IAAIIOUIA OAII UA?OIOA AUII OOA ?IIIIOOOA 
       ?IIO?AII, OI ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation fault.

    *) eO?OA?IAIEA: large_client_header_buffers IA IO?IAIOAAIEOO ?AOAA 
       ?AOAEIAII ? OIOOINIEA keep-alive.
       o?AOEAI iIAEOAIAOO uOA?A.

    *) eO?OA?IAIEA: ? ?AOAIAIIIE $upstream_addr IA UA?EOU?AION ?IOIAAIEE 
       AAOAO; IUEAEA ?IN?EIAOO ? 0.6.18.

    *) eO?OA?IAIEA: AEOAEOE?A fastcgi_catch_stderr IA ?IU?OAYAIA IUEAEO; 
       OA?AOO IIA ?IU?OAYAAO IUEAEO 502, EIOIOOA IIOII IA?OA?EOO IA 
       OIAAOAYEE OAO?AO O ?IIIYOA "fastcgi_next_upstream invalid_header".

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE?U fastcgi_catch_stderr ? 
       IOII?III ?OIAAOOA ?OIEOEIAEI segmentation fault; IUEAEA ?IN?EIAOO ? 
       0.6.10.
       o?AOEAI Manlio Perillo.


eUIAIAIEN ? nginx 0.6.21                                          03.12.2007

    *) eUIAIAIEA: AOIE ? UIA?AIENE ?AOAIAIIUE AEOAEOE?U proxy_pass 
       EO?IIOUOAOON OIIOEI IP-AAOAOA, OI OEAUU?AOO resolver IA IOOII.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE?U proxy_pass c URI-?AOOOA ? 
       OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault; IUEAEA ?IN?EIAOO 
       ? 0.6.19.

    *) eO?OA?IAIEA: AOIE resolver EO?IIOUI?AION IA ?IAO?IOIAE, IA 
       ?IAAAOOE?AAYEE IAOIA kqueue, OI nginx ?UAA?AI alert "name is out of 
       response".
       o?AOEAI aIAOAA iECIAOOIEIO.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?AOAIAIIIE $server_protocol ? 
       FastCGI-?AOAIAOOAE E UA?OIOA, AIEIA EIOIOICI AUIA AIEUEA E UIA?AIEA 
       AEOAEOE?U client_header_buffer_size, nginx ?UAA?AI alert "fastcgi: 
       the request record is too big".

    *) eO?OA?IAIEA: ?OE IAU?III UA?OIOA ?AOOEE HTTP/0.9 E HTTPS OAO?AOO 
       nginx ?IU?OAYAI IAU?IUE IO?AO.


eUIAIAIEN ? nginx 0.6.20                                          28.11.2007

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE?U proxy_pass c URI-?AOOOA ? 
       OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault; IUEAEA ?IN?EIAOO 
       ? 0.6.19.


eUIAIAIEN ? nginx 0.6.19                                          27.11.2007

    *) eO?OA?IAIEA: ?AOOEN 0.6.18 IA OIAEOAIAOO.


eUIAIAIEN ? nginx 0.6.18                                          27.11.2007

    *) eUIAIAIEA: OA?AOO IIAOIO ngx_http_userid_module ? ?IIA EOEE O 
       IIIAOII ?OIAAOOA AIAA?INAO IEEOIOAEOIAU IA ?OAIN OOAOOA.

    *) eUIAIAIEA: ? error_log OA?AOO UA?EOU?AAOON ?IIIAN OOOIEA UA?OIOA 
       ?IAOOI OIIOEI URI.

    *) aIAA?IAIEA: AEOAEOE?A proxy_pass ?IAAAOOE?AAO ?AOAIAIIUA.

    *) aIAA?IAIEA: AEOAEOE?U resolver E resolver_timeout.

    *) aIAA?IAIEA: OA?AOO AEOAEOE?A "add_header last-modified ''" OAAINAO ? 
       UACIII?EA IO?AOA OOOIEO "Last-Modified".

    *) eO?OA?IAIEA: AEOAEOE?A limit_rate IA ?IU?IINIA ?AOAAA?AOO IA ?IIIIE 
       OEIOIOOE, AAOA AOIE AUI OEAUAI I?AIO AIIOUIE IEIEO.


eUIAIAIEN ? nginx 0.6.17                                          15.11.2007

    *) aIAA?IAIEA: ?IAAAOOEA OOOIEE "If-Range" ? UACIII?EA UA?OIOA.
       o?AOEAI aIAEOAIAOO eIAEEIO.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE?U msie_refresh ?I?OIOII 
       UEOAIEOI?AIEOO OOA UEOAIEOI?AIIUA OEI?IIU; IUEAEA ?IN?EIAOO ? 0.6.4.

    *) eO?OA?IAIEA: AEOAEOE?A autoindex IA OAAIOAIA ?OE EO?IIOUI?AIEE 
       "alias /".

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?IAUA?OIOI? ? OAAI?AI ?OIAAOOA IIC 
       ?OIEUIEOE segmentation fault.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE SSL E gzip AIIOUEA IO?AOU IICIE 
       ?AOAAA?AOOON IA ?IIIIOOOA.

    *) eO?OA?IAIEA: AOIE IO?AO ?OIEOEOI?AIIICI OAO?AOA AUI ?AOOEE HTTP/0.9, 
       OI ?AOAIAIIAN $status AUIA OA?IA 0.


eUIAIAIEN ? nginx 0.6.16                                          29.10.2007

    *) eUIAIAIEA: OA?AOO IA Linux EO?IIOUOAOON uname(2) ?IAOOI procfs.
       o?AOEAI eIOA iI?EEI?O.

    *) eO?OA?IAIEA: AOIE ? AEOAEOE?A error_page EO?IIOUI?AION OEI?II "?", 
       OI II UEOAIEOI?AION ?OE ?OIEOEOI?AIEE UA?OIOA; IUEAEA ?IN?EIAOO ? 
       0.6.11.

    *) eO?OA?IAIEA: OI?IAOOEIIOOO O mget.


eUIAIAIEN ? nginx 0.6.15                                          22.10.2007

    *) aIAA?IAIEA: OI?IAOOEIIOOO O Cygwin.
       o?AOEAI ?IAAEIEOO eOOAEI?O.

    *) aIAA?IAIEA: AEOAEOE?A merge_slashes.

    *) aIAA?IAIEA: AEOAEOE?A gzip_vary.

    *) aIAA?IAIEA: AEOAEOE?A server_tokens.

    *) eO?OA?IAIEA: nginx IA OAOEIAEOI?AI URI ? EIIAIAA SSI include.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?AOAIAIIIE ? AEOAEOE?AE charset EIE 
       source_charset IA OOAOOA EIE ?I ?OAIN ?AOAEII?ECOOAAEE ?OIEOEIAEI 
       segmentation fault,

    *) eO?OA?IAIEA: nginx ?IU?OAYAI IUEAEO 400 IA UA?OIOU ?EAA 
       "GET http://www.domain.com HTTP/1.0".
       o?AOEAI James Oakley.

    *) eO?OA?IAIEA: ?IOIA ?AOAIA?OA?IAIEN UA?OIOA O OAIII UA?OIOA O ?IIIYOA 
       AEOAEOE?U error_page nginx ?UOAION OII?A ?OI?EOAOO OAII UA?OIOA; 
       IUEAEA ?IN?EIAOO ? 0.6.7.

    *) eO?OA?IAIEA: ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation fault, AOIE 
       O OAO?AOA, IAOAAAOU?AAYAIO UA?OIO, IA AUI N?II I?OAAAI?I 
       server_name; IUEAEA ?IN?EIAOO ? 0.6.7.


eUIAIAIEN ? nginx 0.6.14                                          15.10.2007

    *) eUIAIAIEA: OA?AOO ?I OIII?AIEA EIIAIAA SSI echo EO?IIOUOAO 
       EIAEOI?AIEA entity.

    *) aIAA?IAIEA: ?AOAIAOO encoding ? EIIAIAA SSI echo.

    *) aIAA?IAIEA: AEOAEOE?O access_log IIOII EO?IIOUI?AOO ?IOOOE AIIEA 
       limit_except.

    *) eO?OA?IAIEA: AOIE ?OA OAO?AOA A?OOOEIA IEAUU?AIEOO IAAIOOO?IUIE, OI 
       AI ?IOOOAII?IAIEN OAAIOIO?IOIAIIOOE O ?OAE OAO?AOI? ?AO OOAII?EION 
       OA?IUI IAIIIO; IUEAEA ?IN?EIAOO ? 0.6.6.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?AOAIAIIUE $date_local E $date_gmt 
       ?IA IIAOIN ngx_http_ssi_filter_module ? OAAI?AI ?OIAAOOA ?OIEOEIAEI 
       segmentation fault.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?EIA??IIII IOIAAI?III IICA ? OAAI?AI 
       ?OIAAOOA IIC ?OIEUIEOE segmentation fault.
       o?AOEAI aIAOAA iECIAOOIEIO.

    *) eO?OA?IAIEA: ngx_http_memcached_module IA OOOAIA?IE?AI 
       $upstream_response_time.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: OAAI?EE ?OIAAOO IIC UAAEEIEOOON ?OE EO?IIOUI?AIEE 
       memcached.

    *) eO?OA?IAIEA: nginx OAO?IUIA?AI ?AOAIAOOU "close" E "keep-alive" ? 
       OOOIEA "Connection" ? UACIII?EA UA?OIOA OIIOEI, AOIE IIE AUIE ? 
       IEOIAI OACEOOOA; IUEAEA ?IN?EIAOO ? 0.6.11.

    *) eO?OA?IAIEA: sub_filter IA OAAIOAI O ?OOOIE OOOIEIE UAIAIU.

    *) eO?OA?IAIEA: ? ?AOOEICA sub_filter.


eUIAIAIEN ? nginx 0.6.13                                          24.09.2007

    *) eO?OA?IAIEA: nginx IA UAEOU?AI ?AEI EAOAIICA AIN UA?OIOA HEAD, AOIE 
       EO?IIOUI?AION autoindex
       o?AOEAI Arkadiusz Patyk.


eUIAIAIEN ? nginx 0.6.12                                          21.09.2007

    *) eUIAIAIEA: ?I?OI?UE ?OIEOE-OAO?AO OAUAAI?I IA OOE IIAOIN: pop3, imap 
       E smtp.

    *) aIAA?IAIEA: ?AOAIAOOU EII?ECOOAAEE --without-mail_pop3_module, 
       --without-mail_imap_module E --without-mail_smtp_module.

    *) aIAA?IAIEA: AEOAEOE?U smtp_greeting_delay E smtp_client_buffer 
       IIAOIN ngx_mail_smtp_module.

    *) eO?OA?IAIEA: wildcard ? EIIAA EIAIE OAO?AOA IA OAAIOAIE; IUEAEA 
       ?IN?EIAOO ? 0.6.9.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE OAUAAINAIIE AEAIEIOAEE PCRE, 
       OAO?IIIOAIIIE ? IAOOAIAAOOIII IAOOA, nginx IA UA?OOEAION IA Solaris.

    *) eO?OA?IAIEA: AEOAEOE?U proxy_hide_header E fastcgi_hide_header IA 
       OEOU?AIE OOOIEE UACIII?EA IO?AOA O EIAIAI AIIOUA 32 OEI?III?.
       o?AOEAI Manlio Perillo.


eUIAIAIEN ? nginx 0.6.11                                          11.09.2007

    *) eO?OA?IAIEA: O??O?EE AEOE?IUE OIAAEIAIEE ?OACAA OIO ?OE 
       EO?IIOUI?AIEE ?I?OI?ICI ?OIEOE-OAO?AOA.

    *) eO?OA?IAIEA: AOIE AUEAIA ?IU?OAYAI OIIOEI UACIII?IE IO?AOA ?OE 
       IAAO?AOEUEOI?AIIII ?OIEOEOI?AIEE, OI nginx UAEOU?AI OIAAEIAIEA O 
       AUEAIAII ?I OAEIAOOO.

    *) eO?OA?IAIEA: nginx IA ?IAAAOOE?AI IAOEIIOEI OOOIE "Connection" ? 
       UACIII?EA UA?OIOA.

    *) eO?OA?IAIEA: AOIE ? OAO?AOA A?OOOEIA AUI UAAAI max_fails, OI ?IOIA 
       ?AO?IE OA IAOAA?IIE ?I?UOEE ?AO OAO?AOA IA?OACAA OOAII?EION OA?IUI 
       IAIIIO; IUEAEA ?IN?EIAOO ? 0.6.6.


eUIAIAIEN ? nginx 0.6.10                                          03.09.2007

    *) aIAA?IAIEA: AEOAEOE?U open_file_cache, open_file_cache_retest E 
       open_file_cache_errors.

    *) eO?OA?IAIEA: OOA?EE OIEAOI?; IUEAEA ?IN?EIAOO ? 0.6.7.

    *) eO?OA?IAIEA: ? OOOIEO UACIII?EA IO?AOA "Content-Type", OEAUAIIOA ? 
       IAOIAA $r->send_http_header(), IA AIAA?INIAOO EIAEOI?EA, OEAUAIIAN ? 
       AEOAEOE?A charset.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE IAOIAA /dev/poll ? OAAI?AI ?OIAAOOA 
       IIC ?OIEUIEOE segmentation fault.


eUIAIAIEN ? nginx 0.6.9                                           28.08.2007

    *) eO?OA?IAIEA: OAAI?EE ?OIAAOO IIC UAAEEIEOOON ?OE EO?IIOUI?AIEE 
       ?OIOIEIIA HTTPS; IUEAEA ?IN?EIAOO ? 0.6.7.

    *) eO?OA?IAIEA: AOIE OAO?AO OIOUAI IA A?OE AAOAOAE EIE ?IOOAE, OI nginx 
       IA UA?OOEAION ?OE EO?IIOUI?AIEE wildcard ? EIIAA EIAIE OAO?AOA.

    *) eO?OA?IAIEA: AEOAEOE?A ip_hash IICIA IA?AOII ?IIA?AOO OAO?AOA EAE 
       IAOAAI?EA.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA amd64; IUEAEA ?IN?EIAOO ? 0.6.8.


eUIAIAIEN ? nginx 0.6.8                                           20.08.2007

    *) eUIAIAIEA: OA?AOO nginx ?UOAAOON OOOAII?EOO AEOAEOE?U 
       worker_priority, worker_rlimit_nofile, worker_rlimit_core, 
       worker_rlimit_sigpending AAU ?OE?EIACEE root'A.

    *) eUIAIAIEA: OA?AOO nginx UEOAIEOOAO OEI?IIU ?OIAAIA E "%" ?OE 
       ?AOAAA?A UA?OIOA OAO?AOO AOOAIOE?EEAAEE ?I?OI?ICI ?OIEOE-OAO?AOA.

    *) eUIAIAIEA: OA?AOO nginx UEOAIEOOAO OEI?II "%" ? ?AOAIAIIIE 
       $memcached_key.

    *) eO?OA?IAIEA: ?OE OEAUAIEE IOIIOEOAIOIICI ?OOE E EII?ECOOAAEIIIIIO 
       ?AEIO ? EA?AOO?A ?AOAIAOOA EIA?A -c nginx I?OAAAINI ?OOO 
       IOIIOEOAIOII EII?ECOOAAEIIIICI ?OA?EEOA; IUEAEA ?IN?EIAOO ? 0.6.6.

    *) eO?OA?IAIEA: nginx IA OAAIOAI IA FreeBSD/sparc64.


eUIAIAIEN ? nginx 0.6.7                                           15.08.2007

    *) eUIAIAIEA: OA?AOO ?OOE, OEAUAIIUA ? AEOAEOE?AE include, 
       auth_basic_user_file, perl_modules, ssl_certificate, 
       ssl_certificate_key E ssl_client_certificate, I?OAAAINAOON 
       IOIIOEOAIOII EAOAIICA EII?ECOOAAEIIIICI ?AEIA nginx.conf, A IA 
       IOIIOEOAIOII ?OA?EEOA.

    *) eUIAIAIEA: ?AOAIAOO --sysconfdir=PATH ? configure O?OAUAI?I.

    *) eUIAIAIEA: AIN IAII?IAIEN IA IAOO ?AOOEE 0.1.x OIUAAI O?AAEAIOIUE 
       OAAIAOEE make upgrade1.

    *) aIAA?IAIEA: AEOAEOE?U server_name E valid_referers ?IAAAOOE?AAO 
       OACOINOIUA ?UOAOAIEN.

    *) aIAA?IAIEA: AEOAEOE?A server ? AIIEA upstream ?IAAAOOE?AAO ?AOAIAOO 
       backup.

    *) aIAA?IAIEA: IIAOIO ngx_http_perl_module ?IAAAOOE?AAO IAOIA 
       $r->discard_request_body.

    *) aIAA?IAIEA: AEOAEOE?A "add_header Last-Modified ..." IAINAO OOOIEO 
       "Last-Modified" ? UACIII?EA IO?AOA.

    *) eO?OA?IAIEA: AOIE IA UA?OIO O OAIII ?IU?OAYAION IO?AO O EIAII HTTP 
       IOIE?IUI IO 200, E ?IOIA UOICI UA?OIOA OIAAEIAIEA ?AOAEIAEII ? 
       OIOOINIEA keep-alive, OI IA OIAAOAYEE UA?OIO nginx ?IU?OAYAI 400.

    *) eO?OA?IAIEA: AOIE ? AEOAEOE?A auth_http AUI UAAAI IA?OA?EIOIUE 
       AAOAO, OI ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation fault.

    *) eO?OA?IAIEA: OA?AOO ?I OIII?AIEA nginx EO?IIOUOAO UIA?AIEA 511 AIN 
       listen backlog IA ?OAE ?IAO?IOIAE, EOIIA FreeBSD.
       o?AOEAI Jiang Hong.

    *) eO?OA?IAIEA: OAAI?EE ?OIAAOO IIC UAAEEIEOOON, AOIE server ? AIIEA 
       upstream AUI ?IIA?AI EAE down; IUEAEA ?IN?EIAOO ? 0.6.6.

    *) eO?OA?IAIEA: sendfilev() ? Solaris OA?AOO IA EO?IIOUOAOON ?OE 
       ?AOAAA?A OAIA UA?OIOA FastCGI-OAO?AOO ?AOAU unix domain OIEAO.


eUIAIAIEN ? nginx 0.6.6                                           30.07.2007

    *) aIAA?IAIEA: ?AOAIAOO --sysconfdir=PATH ? configure.

    *) aIAA?IAIEA: EIAII?AIIUA location'U.

    *) aIAA?IAIEA: ?AOAIAIIOA $args IIOII OOOAIA?IE?AOO O ?IIIYOA set.

    *) aIAA?IAIEA: ?AOAIAIIAN $is_args.

    *) eO?OA?IAIEA: OA?IIIAOIIA OAO?OAAAIAIEA UA?OIOI? E A?OOOEIAI O 
       AIIOUEIE ?AOAIE.

    *) eO?OA?IAIEA: AOIE EIEAIO ? ?I?OI?II ?OIEOE-OAO?AOA UAEOU?AI 
       OIAAEIAIEA, OI nginx IIC IA UAEOU?AOO OIAAEIAIEA O AUEAIAII.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE IAIICI EIOOA ? EA?AOO?A AUEAIAI? AIN 
       ?OIOIEIII? HTTP E HTTPS AAU N?IICI OEAUAIEN ?IOOI?, nginx 
       EO?IIOUI?AI OIIOEI IAEI ?IOO - 80 EIE 443.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA Solaris/amd64 Sun Studio 11 E 
       AIIAA OAIIEIE ?AOOENIE; IUEAEA ?IN?EIAOO ? 0.6.4.


eUIAIAIEN ? nginx 0.6.5                                           23.07.2007

    *) aIAA?IAIEA: ?AOAIAIIAN $nginx_version.
       o?AOEAI iEEIIAA cOA?OEO.

    *) aIAA?IAIEA: ?I?OI?UE ?OIEOE-OAO?AO ?IAAAOOE?AAO AUTHENTICATE ? 
       OAOEIA IMAP.
       o?AOEAI iAEOEIO aOIEIO.

    *) aIAA?IAIEA: ?I?OI?UE ?OIEOE-OAO?AO ?IAAAOOE?AAO STARTTLS ? OAOEIA 
       SMTP.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: OA?AOO nginx UEOAIEOOAO ?OIAAI ? ?AOAIAIIIE 
       $memcached_key.

    *) eO?OA?IAIEA: nginx IA?OA?EIOII OIAEOAION Sun Studio IA 
       Solaris/amd64.
       o?AOEAI Jiang Hong.

    *) eO?OA?IAIEA: IAUIA?EOAIOIUE ?IOAIAEAIOIUE IUEAIE.
       o?AOEAI Coverity's Scan.


eUIAIAIEN ? nginx 0.6.4                                           17.07.2007

    *) aAUI?AOIIOOO: ?OE EO?IIOUI?AIEE AEOAEOE?U msie_refresh AUI ?IUIIOAI 
       XSS.
       o?AOEAI iAEOEIO aICOEO.

    *) eUIAIAIEA: AEOAEOE?U proxy_store E fastcgi_store EUIAIAIU.

    *) aIAA?IAIEA: AEOAEOE?U proxy_store_access E fastcgi_store_access.

    *) eO?OA?IAIEA: nginx IA OAAIOAI IA Solaris/sparc64, AOIE AUI OIAOAI 
       Sun Studio.
       o?AOEAI aIAOAA iECIAOOIEIO.

    *) eUIAIAIEA: IAEIA IUEAEE ? Sun Studio 12.
       o?AOEAI Jiang Hong.


eUIAIAIEN ? nginx 0.6.3                                           12.07.2007

    *) aIAA?IAIEA: AEOAEOE?U proxy_store E fastcgi_store.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE?U auth_http_header ? OAAI?AI 
       ?OIAAOOA IIC ?OIEUIEOE segmentation fault.
       o?AOEAI iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: AOIE EO?IIOUI?AION IAOIA AOOAIOE?EEAAEE CRAM-MD5, II II 
       IA AUI OAUOAU?I, OI ? OAAI?AI ?OIAAOOA ?OIEOEIAEI segmentation fault.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?OIOIEIIA HTTPS ? AEOAEOE?A 
       proxy_pass ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault.

    *) eO?OA?IAIEA: ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault, 
       AOIE EO?IIOUI?AION IAOIA eventport.

    *) eO?OA?IAIEA: AEOAEOE?U proxy_ignore_client_abort E 
       fastcgi_ignore_client_abort IA OAAIOAIE; IUEAEA ?IN?EIAOO ? 0.5.13.


eUIAIAIEN ? nginx 0.6.2                                           09.07.2007

    *) eO?OA?IAIEA: AOIE UACIII?IE IO?AOA AUI OAUAAI?I ? FastCGI-UA?EONE, 
       OI nginx ?AOAAA?AI EIEAIOO IOOIO ? OAEEE UACIII?EAE.


eUIAIAIEN ? nginx 0.6.1                                           17.06.2007

    *) eO?OA?IAIEA: ? ?AOOEICA SSI.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE OAAI?IIICI ?IAUA?OIOA ? SSI 
       ?IOIAAOAYEE ?IAUA?OIO IIEAIOIICI ?AEIA IIC IOAA?AOOON EIEAIOO ? 
       IA?AOIII ?IONAEA.

    *) eO?OA?IAIEA: AIIOUEA ?EIA?AIEN ? SSI, OIEOAI?IIUA ?I ?OAIAIIUA 
       ?AEIU, ?AOAAA?AIEOO IA ?IIIIOOOA.

    *) eO?OA?IAIEA: UIA?AIEA perl'I?IE ?AOAIAIIIE $$ IIAOIN 
       ngx_http_perl_module AUII OA?II IIIAOO CIA?IICI ?OIAAOOA.


eUIAIAIEN ? nginx 0.6.0                                           14.06.2007

    *) aIAA?IAIEA: AEOAEOE?U "server_name", "map", and "valid_referers" 
       ?IAAAOOE?AAO IAOEE ?EAA "www.example.*".


eUIAIAIEN ? nginx 0.5.25                                          11.06.2007

    *) eO?OA?IAIEA: nginx IA OIAEOAION O ?AOAIAOOII 
       --without-http_rewrite_module; IUEAEA ?IN?EIAOO ? 0.5.24.


eUIAIAIEN ? nginx 0.5.24                                          06.06.2007

    *) aAUI?AOIIOOO: AEOAEOE?A ssl_verify_client IA OAAIOAIA, AOIE UA?OIO 
       ?U?IIINION ?I ?OIOIEIIO HTTP/0.9.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE OOAOEN ?AOOO IO?AOA IICIA 
       ?AOAAA?AOOON IAOOAOIE; IUEAEA ?IN?EIAOO ? 0.5.23.


eUIAIAIEN ? nginx 0.5.23                                          04.06.2007

    *) aIAA?IAIEA: IIAOIO ngx_http_ssl_module ?IAAAOOE?AAO OAOUEOAIEA TLS 
       Server Name Indication.

    *) aIAA?IAIEA: AEOAEOE?A fastcgi_catch_stderr.
       o?AOEAI iEEIIAA cOA?OEO, ?OIAEO OWOX.

    *) eO?OA?IAIEA: IA iEIOEOA ? IOII?III ?OIAAOOA ?OIEOEIAEI segmentation 
       fault, AOIE A?A ?EOOOAIOIUE OAO?AOA AIIOIU bind()EOON E 
       ?AOAOAEAAYEION ?IOOAI.

    *) eO?OA?IAIEA: AOIE nginx AUI OIAOAI O IIAOIAI ngx_http_perl_module E 
       perl ?IAAAOOE?AI ?IOIEE, OI ?I ?OAIN ?OIOIE ?AOAEII?ECOOAAEE 
       ?UAA?AIEOO IUEAEE "panic: MUTEX_LOCK" E "perl_parse() failed".

    *) eO?OA?IAIEA: ? EO?IIOUI?AIEE ?OIOIEIIA HTTPS ? AEOAEOE?A proxy_pass.


eUIAIAIEN ? nginx 0.5.22                                          29.05.2007

    *) eO?OA?IAIEA: AIIOUIA OAII UA?OIOA IICII IA ?AOAAA?AOOON AUEAIAO; 
       IUEAEA ?IN?EIAOO ? 0.5.21.


eUIAIAIEN ? nginx 0.5.21                                          28.05.2007

    *) eO?OA?IAIEA: AOIE ?IOOOE OAO?AOA I?EOAII AIIOUA ?OEIAOII AAONOE 
       location'I?, OI location'U, UAAAIIUA O ?IIIYOA OACOINOIICI 
       ?UOAOAIEN, IICIE ?U?IIINOOON IA ? OII, ?IONAEA, ? EAEII IIE I?EOAIU.

    *) eO?OA?IAIEA: IA 64-AEOIIE ?IAO?IOIA OAAI?EE ?OIAAOO IIC UAAEEIEOOON, 
       AOIE 33-OEE ?I O??OO EIE ?IOIAAOAYEE AUEAIA O?AI.
       o?AOEAI aIOIIO ?I?AOI?O.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEAIEIOAEE PCRE IA Solaris/sparc64 
       IIC ?OIEUIEOE bus error.
       o?AOEAI aIAOAA iECIAOOIEIO.

    *) eO?OA?IAIEA: ? EO?IIOUI?AIEE ?OIOIEIIA HTTPS ? AEOAEOE?A proxy_pass.


eUIAIAIEN ? nginx 0.5.20                                          07.05.2007

    *) aIAA?IAIEA: AEOAEOE?A sendfile_max_chunk.

    *) aIAA?IAIEA: ?AOAIAIIUA "$http_...", "$sent_http_..." E 
       "$upstream_http_..." IIOII IAINOO AEOAEOE?IE set.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE SSI-EIIAIAU 'if expr="$var = /"' ? 
       OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault.

    *) eO?OA?IAIEA: UA?AOUAAYAN OOOIEA multipart range IO?AOA ?AOAAA?AIAOO 
       IA?AOII.
       o?AOEAI Evan Miller.

    *) eO?OA?IAIEA: nginx IA OAAIOAI IA Solaris/sparc64, AOIE AUI OIAOAI 
       Sun Studio.
       o?AOEAI aIAOAA iECIAOOIEIO.

    *) eO?OA?IAIEA: IIAOIO ngx_http_perl_module IA OIAEOAION make ? 
       Solaris.
       o?AOEAI aIAOAA iECIAOOIEIO.


eUIAIAIEN ? nginx 0.5.19                                          24.04.2007

    *) eUIAIAIEA: UIA?AIEA ?AOAIAIIIE $request_time OA?AOO UA?EOU?AAOON O 
       OI?IIOOOA AI IEIIEOAEOIA.

    *) eUIAIAIEA: IAOIA $r->rflush ? IIAOIA ngx_http_perl_module 
       ?AOAEIAII?AI ? $r->flush.

    *) aIAA?IAIEA: ?AOAIAIIAN $upstream_addr.

    *) aIAA?IAIEA: AEOAEOE?U proxy_headers_hash_max_size E 
       proxy_headers_hash_bucket_size.
       o?AOEAI ?IIIAUIUOO eIOOUOEI.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE sendfile E limit_rate IA 64-AEOIUE 
       ?IAO?IOIAE IAIOUN AUII ?AOAAA?AOO ?AEIU AIIOUA 2G.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE sendfile IA 64-AEOIII Linux IAIOUN 
       AUII ?AOAAA?AOO ?AEIU AIIOUA 2G.


eUIAIAIEN ? nginx 0.5.18                                          19.04.2007

    *) aIAA?IAIEA: IIAOIO ngx_http_sub_filter_module.

    *) aIAA?IAIEA: ?AOAIAIIUA "$upstream_http_...".

    *) aIAA?IAIEA: OA?AOO ?AOAIAIIUA $upstream_status E 
       $upstream_response_time OIAAOOAO AAIIUA I ?OAE IAOAYAIENE E 
       A?OOOEIAI, OAAIAIIUI AI X-Accel-Redirect.

    *) eO?OA?IAIEA: AOIE nginx AUI OIAOAI O IIAOIAI ngx_http_perl_module E 
       perl IA ?IAAAOOE?AI multiplicity, OI ?IOIA ?AO?IE ?AOAEII?ECOOAAEE E 
       ?IOIA ?IIO?AIEN IAAICI OECIAIA ? IOII?III ?OIAAOOA ?OIEOEIAEI 
       segmentation fault; IUEAEA ?IN?EIAOO ? 0.5.9.

    *) eO?OA?IAIEA: AOIE perl IA ?IAAAOOE?AI multiplicity, OI ?IOIA 
       ?AOAEII?ECOOAAEE ?AOII?UE EIA IA OAAIOAI; IUEAEA ?IN?EIAOO ? 0.3.38.


eUIAIAIEN ? nginx 0.5.17                                          02.04.2007

    *) eUIAIAIEA: OA?AOO nginx AIN IAOIAA TRACE ?OACAA ?IU?OAYAAO EIA 405.

    *) aIAA?IAIEA: OA?AOO nginx ?IAAAOOE?AAO AEOAEOE?O include ?IOOOE AIIEA 
       types.

    *) eO?OA?IAIEA: EO?IIOUI?AIEA ?AOAIAIIIE $document_root ? AEOAEOE?A 
       root E alias UA?OAYAII: III ?UUU?AII OAEOOOE?IIA ?AOA?IIIAIEA OOAEA.

    *) eO?OA?IAIEA: ? EO?IIOUI?AIEE ?OIOIEIIA HTTPS ? AEOAEOE?A proxy_pass.

    *) eO?OA?IAIEA: ? IAEIOIOUE OIO?ANE IAEUUEOOAIUA ?AOAIAIIUA (OAEEA, EAE 
       $uri) ?IU?OAYAIE OOAOIA UAEUUEOI?AIIIA UIA?AIEA.


eUIAIAIEN ? nginx 0.5.16                                          26.03.2007

    *) eO?OA?IAIEA: ? EA?AOO?A EIA?A AIN EUUA ? AEOAEOE?A ip_hash IA 
       EO?IIOUI?AIAOO OAOO EIAOOA o.
       o?AOEAI ?A?IO nOEI?IIO.

    *) eO?OA?IAIEA: AOIE ? OOOIEA "Content-Type" ? UACIII?EA IO?AOA AUEAIAA 
       AUI OEAUAI charset E OOOIEA UA?AOUAIAOO OEI?IIII ";", OI ? OAAI?AI 
       ?OIAAOOA IIC ?OIEUIEOE segmentation fault; IUEAEA ?IN?EIAOO ? 0.3.50.

    *) eO?OA?IAIEA: IUEAEE "[alert] zero size buf" ?OE OAAIOA O 
       FastCGI-OAO?AOII, AOIE OAII UA?OIOA, UA?EOAIIIA ?I ?OAIAIIUE ?AEI, 
       AUII EOAOII 32K.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA Solaris AAU ?AOAIAOOA 
       --with-debug; IUEAEA ?IN?EIAOO ? 0.5.15.


eUIAIAIEN ? nginx 0.5.15                                          19.03.2007

    *) aIAA?IAIEA: ?I?OI?UE ?OIEOE-OAO?AO ?IAAAOOE?AAO AOOAIOE?EAEOI?AIIIA 
       SMTP-?OIEOEOI?AIEA E AEOAEOE?U smtp_auth, smtp_capablities E 
       xclient.
       o?AOEAI aIOIIO aOAIEII?O E iAEOEIO aOIEIO.

    *) aIAA?IAIEA: OA?AOO keep-alive OIAAEIAIEN UAEOU?AAOON OOAUO OA ?I 
       ?IIO?AIEE OECIAIA ?AOAEII?ECOOAAEE.

    *) eUIAIAIEA: AEOAEOE?U imap E auth ?AOAEIAII?AIU OIIO?AOOO?AIII ? mail 
       E pop3_auth.

    *) eO?OA?IAIEA: AOIE EO?IIOUI?AION IAOIA AOOAIOE?EEAAEE CRAM-MD5 E IA 
       AUI OAUOAU?I IAOIA APOP, OI ? OAAI?AI ?OIAAOOA ?OIEOEIAEI 
       segmentation fault.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE?U starttls only ? ?OIOIEIIA 
       POP3 nginx OAUOAUAI AOOAIOE?EEAAEA AAU ?AOAEIAA ? OAOEI SSL.

    *) eO?OA?IAIEA: OAAI?EA ?OIAAOOU IA ?UEIAEIE ?IOIA ?AOAEII?ECOOAAEE E 
       IA ?AOAIOEOU?AIE IICE, AOIE EO?IIOUI?AION IAOIA eventport.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE?U ip_hash OAAI?EE ?OIAAOO IIC 
       UAAEEIEOOON.

    *) eO?OA?IAIEA: OA?AOO nginx IA ?EUAO ? IIC IAEIOIOUA alert'U, AOIE 
       EO?IIOUOAOON IAOIAU eventport EIE /dev/poll.


eUIAIAIEN ? nginx 0.5.14                                          23.02.2007

    *) eO?OA?IAIEA: nginx ECIIOEOI?AI IEUIEA UAEOU?AAYEA OEIAEE "}" ? EIIAA 
       EII?ECOOAAEIIIICI ?AEIA.


eUIAIAIEN ? nginx 0.5.13                                          19.02.2007

    *) aIAA?IAIEA: IAOIAU COPY E MOVE.

    *) eO?OA?IAIEA: IIAOIO ngx_http_realip_module OOOAIA?IE?AI IOOIO AIN 
       UA?OIOI?, ?AOAAAIIUE ?I keep-alive OIAAEIAIEA.

    *) eO?OA?IAIEA: nginx IA OAAIOAI IA 64-AEOIII big-endian Linux.
       o?AOEAI aIAOAA iECIAOOIEIO.

    *) eO?OA?IAIEA: ?OE ?IIO?AIEE OIEUEII AIEIIIE EIIAIAU IMAP/POP3-?OIEOE 
       OA?AOO OOAUO UAEOU?AAO OIAAEIAIEA, A IA ?I OAEIAOOO.

    *) eO?OA?IAIEA: AOIE ?OE EO?IIOUI?AIEE IAOIAA epoll EIEAIO UAEOU?AI 
       ?OAOAA?OAIAIII OIAAEIAIEA OI O?IAE OOIOIIU, OI nginx UAEOU?AI UOI 
       OIAAEIAIEA OIIOEI ?I EOOA?AIEE OAEIAOOA IA ?AOAAA?O.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA ?IAO?IOIAE, IOIE?IUE IO i386, 
       amd64, sparc E ppc; IUEAEA ?IN?EIAOO ? 0.5.8.


eUIAIAIEN ? nginx 0.5.12                                          12.02.2007

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA ?IAO?IOIAE, IOIE?IUE IO i386, 
       amd64, sparc E ppc; IUEAEA ?IN?EIAOO ? 0.5.8.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?OAIAIIUE ?AEII? ? ?OAIN OAAIOU O 
       FastCGI-OAO?AOII ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation 
       fault; IUEAEA ?IN?EIAOO ? 0.5.8.

    *) eO?OA?IAIEA: AOIE ?AOAIAIIAN $fastcgi_script_name UA?EOU?AIAOO ? 
       IIC, OI ? OAAI?AI ?OIAAOOA IIC ?OIEUIEOE segmentation fault.

    *) eO?OA?IAIEA: ngx_http_perl_module IA OIAEOAION IA Solaris.


eUIAIAIEN ? nginx 0.5.11                                          05.02.2007

    *) aIAA?IAIEA: OA?AOO configure I?OAAAINAO AEAIEIOAEO PCRE ? 
       MacPorts.
       o?AOEAI Chris McGrath.

    *) eO?OA?IAIEA: IO?AO AUI IA?AOIUI, AOIE UA?OAUE?AIIOO IAOEIIOEI 
       AEA?AUIII?; IUEAEA ?IN?EIAOO ? 0.5.6.

    *) eO?OA?IAIEA: AEOAEOE?A create_full_put_path IA IICIA OIUAA?AOO 
       ?OIIAOOOI?IUA EAOAIICE, AOIE IA AUIA OOOAII?IAIA AEOAEOE?A 
       dav_access.
       o?AOEAI Evan Miller.

    *) eO?OA?IAIEA: ?IAOOI EIAI? IUEAIE "400" E "408" ? access_log IIC 
       UA?EOU?AOOON EIA "0".

    *) eO?OA?IAIEA: ?OE OAIOEA O I?OEIEUAAEAE -O2 ? OAAI?AI ?OIAAOOA IIC 
       ?OIEUIEOE segmentation fault.


eUIAIAIEN ? nginx 0.5.10                                          26.01.2007

    *) eO?OA?IAIEA: ?I ?OAIN IAII?IAIEN EO?IIINAIICI ?AEIA II?UE ?OIAAOO IA 
       IAOIAAI?AI OIOUAAYEA OIEAOU; IUEAEA ?IN?EIAOO ? 0.5.9.

    *) eO?OA?IAIEA: ?OE OAIOEA O I?OEIEUAAEAE -O2 ? OAAI?AI ?OIAAOOA IIC 
       ?OIEUIEOE segmentation fault; IUEAEA ?IN?EIAOO ? 0.5.1.


eUIAIAIEN ? nginx 0.5.9                                           25.01.2007

    *) eUIAIAIEA: IIAOIO ngx_http_memcached_module OA?AOO ? EA?AOO?A EIA?A 
       EO?IIOUOAO UIA?AIEA ?AOAIAIIIE $memcached_key.

    *) aIAA?IAIEA: ?AOAIAIIAN $memcached_key.

    *) aIAA?IAIEA: ?AOAIAOO clean ? AEOAEOE?A client_body_in_file_only.

    *) aIAA?IAIEA: AEOAEOE?A env.

    *) aIAA?IAIEA: AEOAEOE?A sendfile OAAIOAAO ?IOOOE AIIEA if.

    *) aIAA?IAIEA: OA?AOO ?OE IUEAEA UA?EOE ? access_log nginx UA?EOU?AAO 
       OIIAYAIEA ? error_log, II IA ?AYA IAIICI OAUA ? IEIOOO.

    *) eO?OA?IAIEA: AEOAEOE?A "access_log off" IA ?OACAA UA?OAYAIA UA?EOO ? 
       IIC.


eUIAIAIEN ? nginx 0.5.8                                           19.01.2007

    *) eO?OA?IAIEA: AOIE EO?IIOUI?AIAOO AEOAEOE?A 
       "client_body_in_file_only on" E OAII UA?OIOA AUII IAAIIOUIA, OI IIC 
       ?OIEUIEOE segmentation fault.

    *) eO?OA?IAIEA: ?OIEOEIAEI segmentation fault, AOIE EO?IIOUI?AIEOO 
       AEOAEOE?U "client_body_in_file_only on" E 
       "proxy_pass_request_body off" EIE "fastcgi_pass_request_body off", E 
       AAIAION ?AOAEIA E OIAAOAYAIO AUEAIAO.

    *) eO?OA?IAIEA: AOIE ?OE EO?IIOUI?AIEE AEOAEOE?U "proxy_buffering off" 
       OIAAEIAIEA O EIEAIOII AUII IAAEOE?II, OI III UAEOU?AIIOO ?I 
       OAEIAOOO, UAAAIIIIO AEOAEOE?IE send_timeout; IUEAEA ?IN?EIAOO ? 
       0.4.7.

    *) eO?OA?IAIEA: AOIE ?OE EO?IIOUI?AIEE IAOIAA epoll EIEAIO UAEOU?AI 
       ?OAOAA?OAIAIII OIAAEIAIEA OI O?IAE OOIOIIU, OI nginx UAEOU?AI UOI 
       OIAAEIAIEA OIIOEI ?I EOOA?AIEE OAEIAOOA IA ?AOAAA?O.

    *) eO?OA?IAIEA: IUEAEE "[alert] zero size buf" ?OE OAAIOA O 
       FastCGI-OAO?AOII.

    *) eO?OA?IAIEA IUEAIE ? AEOAEOE?A limit_zone.


eUIAIAIEN ? nginx 0.5.7                                           15.01.2007

    *) aIAA?IAIEA: I?OEIEUAAEN EO?IIOUI?AIEN ?AINOE ? ssl_session_cache.

    *) eO?OA?IAIEA IUEAIE ? AEOAEOE?AE ssl_session_cache E limit_zone.

    *) eO?OA?IAIEA: IA OOAOOA EIE ?I ?OAIN ?AOAEII?ECOOAAEE ?OIEOEIAEI 
       segmentation fault, AOIE AEOAEOE?U ssl_session_cache EIE limit_zone 
       EO?IIOUI?AIEOO IA 64-AEOIUE ?IAO?IOIAE.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE? add_before_body EIE 
       add_after_body ?OIEOEIAEI segmentation fault, AOIE ? UACIII?EA 
       IO?AOA IAO OOOIEE "Content-Type".

    *) eO?OA?IAIEA: AEAIEIOAEA OpenSSL ?OACAA OIAEOAIAOO O ?IAAAOOEIE 
       ?IOIEI?.
       o?AOEAI aAIO e?AII?O.

    *) eO?OA?IAIEA: OI?IAOOEIIOOO AEAIEIOAEE PCRE-6.5+ E EII?EINOIOA icc.


eUIAIAIEN ? nginx 0.5.6                                           09.01.2007

    *) eUIAIAIEA: OA?AOO IIAOIO ngx_http_index_module ECIIOEOOAO ?OA 
       IAOIAU, EOIIA GET, HEAD E POST.

    *) aIAA?IAIEA: IIAOIO ngx_http_limit_zone_module.

    *) aIAA?IAIEA: ?AOAIAIIAN $binary_remote_addr.

    *) aIAA?IAIEA: AEOAEOE?U ssl_session_cache IIAOIAE ngx_http_ssl_module 
       E ngx_imap_ssl_module.

    *) aIAA?IAIEA: IAOIA DELETE ?IAAAOOE?AAO OAEOOOE?IIA OAAIAIEA.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE $r->sendfile() byte-ranges 
       ?AOAAA?AIEOO IA?AOII.


eUIAIAIEN ? nginx 0.5.5                                           24.12.2006

    *) eUIAIAIEA: EIA? -v AIIOUA IA ?U?IAEO EI?IOIAAEA I EII?EINOIOA.

    *) aIAA?IAIEA: EIA? -V.

    *) aIAA?IAIEA: AEOAEOE?A worker_rlimit_core ?IAAAOOE?AAO OEAUAIEA 
       OAUIAOA ? K, M E G.

    *) eO?OA?IAIEA: IIAOIO nginx.pm OA?AOO IIOAO OOOAIA?IE?AOOON 
       IA?OE?EIACEOI?AIIUI ?IIOUI?AOAIAI.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE IAOIAI? $r->request_body EIE 
       $r->request_body_file IIC ?OIEUIEOE segmentation fault.

    *) eO?OA?IAIEA: IUEAIE, O?AAE?E?IUE AIN ?IAO?IOIU ppc.


eUIAIAIEN ? nginx 0.5.4                                           15.12.2006

    *) aIAA?IAIEA: AEOAEOE?O perl IIOII EO?IIOUI?AOO ?IOOOE AIIEA 
       limit_except.

    *) eO?OA?IAIEA: IIAOIO ngx_http_dav_module OOAAI?AI OOOIEO "Date" ? 
       UACIII?EA UA?OIOA AIN IAOIAA DELETE.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE IAIICI ?AOAIAOOA ? AEOAEOE?A 
       dav_access nginx IIC OIIAYEOO IA IUEAEA ? EII?ECOOAAEE.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?AOAIAIIIE $host IIC ?OIEUIEOE 
       segmentation fault; IUEAEA ?IN?EIAOO ? 0.4.14.


eUIAIAIEN ? nginx 0.5.3                                           13.12.2006

    *) aIAA?IAIEA: IIAOIO ngx_http_perl_module ?IAAAOOE?AAO IAOIAU 
       $r->status, $r->log_error E $r->sleep.

    *) aIAA?IAIEA: IAOIA $r->variable ?IAAAOOE?AAO ?AOAIAIIUA, IAI?EOAIIUA 
       ? EII?ECOOAAEE nginx'A.

    *) eO?OA?IAIEA: IAOIA $r->has_request_body IA OAAIOAI.


eUIAIAIEN ? nginx 0.5.2                                           11.12.2006

    *) eO?OA?IAIEA: AOIE ? AEOAEOE?AE proxy_pass EO?IIOUI?AIIOO EIN, 
       OEAUAIIIA ? upstream, OI nginx ?UOAION IAEOE IP-AAOAO UOICI EIAIE; 
       IUEAEA ?IN?EIAOO ? 0.5.1.


eUIAIAIEN ? nginx 0.5.1                                           11.12.2006

    *) eO?OA?IAIEA: AEOAEOE?A post_action IICIA IA OAAIOAOO ?IOIA 
       IAOAA?IICI UA?AOUAIEN UA?OIOA.

    *) eUIAIAIEA: IAEIA IUEAEE ? Eudora AIN Mac; IUEAEA ?IN?EIAOO ? 
       0.4.11.
       o?AOEAI Bron Gondwana.

    *) eO?OA?IAIEA: ?OE OEAUAIEE ? AEOAEOE?A fastcgi_pass EIAIE I?EOAIIICI 
       upstream'A ?UAA?AIIOO OIIAYAIEA "no port in upstream"; IUEAEA 
       ?IN?EIAOO ? 0.5.0.

    *) eO?OA?IAIEA: AOIE ? AEOAEOE?AE proxy_pass E fastcgi_pass 
       EO?IIOUI?AIEOO IAEIAEI?UE EIAIA OAO?AOI?, II O OAUIUIE ?IOOAIE, OI 
       UOE AEOAEOE?U EO?IIOUI?AIE ?AO?UE I?EOAIIUE ?IOO; IUEAEA ?IN?EIAOO ? 
       0.5.0.

    *) eO?OA?IAIEA: AOIE ? AEOAEOE?AE proxy_pass E fastcgi_pass 
       EO?IIOUI?AIEOO unix domain OIEAOU, OI UOE AEOAEOE?U EO?IIOUI?AIE 
       ?AO?UE I?EOAIIUE OIEAO; IUEAEA ?IN?EIAOO ? 0.5.0.

    *) eO?OA?IAIEA: ngx_http_auth_basic_module ECIIOEOI?AI ?IIOUI?AOAIN, 
       AOIE II AUI OEAUAI ? ?IOIAAIAE OOOIEA ?AEIA ?AOIIAE E ?IOIA ?AOIIN 
       IA AUII ?AOA?IAA OOOIEE, ?IU?OAOA EAOAOEE EIE OEI?IIA ":".

    *) eO?OA?IAIEA: ?AOAIAIIAN $upstream_response_time IICIA AUOO OA?IA 
       "0.000", EION ?OAIN IAOAAIOEE AUII AIIOUA 1 IEIIEOAEOIAU.


eUIAIAIEN ? nginx 0.5.0                                           04.12.2006

    *) eUIAIAIEA: ?AOAIAOOU ? ?EAA "%name" ? AEOAEOE?A log_format AIIOUA IA 
       ?IAAAOOE?AAOON.

    *) eUIAIAIEA: AEOAEOE?U proxy_upstream_max_fails, 
       proxy_upstream_fail_timeout, fastcgi_upstream_max_fails, E 
       fastcgi_upstream_fail_timeout, memcached_upstream_max_fails E 
       memcached_upstream_fail_timeout AIIOUA IA ?IAAAOOE?AAOON.

    *) aIAA?IAIEA: AEOAEOE?A server ? AIIEA upstream ?IAAAOOE?AAO ?AOAIAOOU 
       max_fails, fail_timeout E down.

    *) aIAA?IAIEA: AEOAEOE?A ip_hash ? AIIEA upstream.

    *) aIAA?IAIEA: OOAOOO WAIT ? OOOIEA "Auth-Status" ? UACIII?EA IO?AOA 
       OAO?AOA AOOAIOE?EEAAEE IMAP/POP3 ?OIEOE.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA 64-AEOIUE ?IAO?IOIAE; IUEAEA 
       ?IN?EIAOO ? 0.4.14.


eUIAIAIEN ? nginx 0.4.14                                          27.11.2006

    *) aIAA?IAIEA: AEOAEOE?A proxy_pass_error_message ? IMAP/POP3 ?OIEOE.

    *) aIAA?IAIEA: OA?AOO configure I?OAAAINAO AEAIEIOAEO PCRE IA FreeBSD, 
       Linux E NetBSD.

    *) eO?OA?IAIEA: ngx_http_perl_module IA OAAIOAI O ?AOIII, OIAOAIIUI O 
       ?IAAAOOEIE ?IOIEI?; IUEAEA ?IN?EIAOO ? 0.3.38.

    *) eO?OA?IAIEA: ngx_http_perl_module IA OAAIOAI EIOOAEOII, AOIE ?AOI 
       ?UUU?AION OAEOOOE?II.

    *) eO?OA?IAIEA: nginx ECIIOEOI?AI EIN OAO?AOA ? OOOIEA UA?OIOA.

    *) eO?OA?IAIEA: AOIE FastCGI OAO?AO ?AOAAA?AI IIICI ? stderr, OI 
       OAAI?EE ?OIAAOO IIC UAAEEIEOOON.

    *) eO?OA?IAIEA: ?OE EUIAIAIEE OEOOAIIICI ?OAIAIE ?AOAIAIIAN 
       $upstream_response_time IICIA AUOO IOOEAAOAIOIIE.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE POP3 OAO?AOO AOOAIOE?EEAAEE IMAP/POP3 
       ?OIEOE IA ?AOAAA?AION ?AOAIAOO Auth-Login-Attempt.

    *) eO?OA?IAIEA: ?OE IUEAEA OIAAEIAIEN O OAO?AOII AOOAIOE?EEAAEE 
       IMAP/POP3 ?OIEOE IIC ?OIEUIEOE segmentation fault.


eUIAIAIEN ? nginx 0.4.13                                          15.11.2006

    *) aIAA?IAIEA: AEOAEOE?O proxy_pass IIOII EO?IIOUI?AOO ?IOOOE AIIEA 
       limit_except.

    *) aIAA?IAIEA: AEOAEOE?A limit_except ?IAAAOOE?AAO ?OA WebDAV IAOIAU.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE?U add_before_body AAU 
       AEOAEOE?U add_after_body IO?AO ?AOAAA?AION IA ?IIIIOOOA.

    *) eO?OA?IAIEA: AIIOUIA OAII UA?OIOA IA ?OEIEIAIIOO, AOIE 
       EO?IIOUI?AIEOO IAOIA epoll E deferred accept().

    *) eO?OA?IAIEA: AIN IO?AOI? IIAOIN ngx_http_autoindex_module IA 
       ?UOOA?INIAOO EIAEOI?EA; IUEAEA ?IN?EIAOO ? 0.3.50.

    *) eO?OA?IAIEA: IUEAEE "[alert] zero size buf" ?OE OAAIOA O 
       FastCGI-OAO?AOII;

    *) eO?OA?IAIEA: ?AOAIAOO EII?ECOOAAEE --group= ECIIOEOI?AION.
       o?AOEAI Thomas Moschny.

    *) eO?OA?IAIEA: 50-E ?IAUA?OIO ? SSI IO?AOA IA OAAIOAI; IUEAEA 
       ?IN?EIAOO ? 0.3.50.


eUIAIAIEN ? nginx 0.4.12                                          31.10.2006

    *) aIAA?IAIEA: IIAOIO ngx_http_perl_module ?IAAAOOE?AAO IAOIA 
       $r->variable.

    *) eO?OA?IAIEA: ?OE ?EIA?AIEE ? IO?AO AIIOUICI OOAOE?AOEICI ?AEIA O 
       ?IIIYOA SSI IO?AO IIC ?AOAAA?AOOON IA ?IIIIOOOA.

    *) eO?OA?IAIEA: nginx IA OAEOAI "#fragment" ? URI.


eUIAIAIEN ? nginx 0.4.11                                          25.10.2006

    *) aIAA?IAIEA: POP3 ?OIEOE ?IAAAOOE?AAO AUTH LOIGN PLAIN E CRAM-MD5.

    *) aIAA?IAIEA: IIAOIO ngx_http_perl_module ?IAAAOOE?AAO IAOIA 
       $r->allow_ranges.

    *) eO?OA?IAIEA: ?OE ?EIA??IIIE ?IAAAOOEA EIIAIAU APOP ? POP3 ?OIEOE 
       IICIE IA OAAIOAOO EIIAIAU USER/PASS; IUEAEA ?IN?EIAOO ? 0.4.10.


eUIAIAIEN ? nginx 0.4.10                                          23.10.2006

    *) aIAA?IAIEA: POP3 ?OIEOE ?IAAAOOE?AAO APOP.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE IAOIAI? select, poll E /dev/poll ?I 
       ?OAIN IOEAAIEN IO?AOA IO OAO?AOA AOOAIOE?EEAAEE IMAP/POP3 ?OIEOE 
       IACOOOAI ?OIAAOOIO.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?AOAIAIIIE $server_addr ? AEOAEOE?A 
       map IIC ?OIEUIEOE segmentation fault.

    *) eO?OA?IAIEA: IIAOIO ngx_http_flv_module IA ?IAAAOOE?AI byte ranges 
       AIN ?IIIUE IO?AOI?; IUEAEA ?IN?EIAOO ? 0.4.7.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA Debian amd64; IUEAEA ?IN?EIAOO ? 
       0.4.9.


eUIAIAIEN ? nginx 0.4.9                                           13.10.2006

    *) aIAA?IAIEA: ?AOAIAOO set ? EIIAIAA SSI include.

    *) aIAA?IAIEA: IIAOIO ngx_http_perl_module OA?AOO ?OI?AONAO ?AOOEA 
       IIAOIN nginx.pm.


eUIAIAIEN ? nginx 0.4.8                                           11.10.2006

    *) eO?OA?IAIEA: AOIE AI EIIAIAU SSI include O ?AOAIAOOII wait 
       ?U?IIINIAOO AY? IAIA EIIAIAA SSI include, OI ?AOAIAOO wait IIC IA 
       OAAIOAOO.

    *) eO?OA?IAIEA: IIAOIO ngx_http_flv_module AIAA?INI FLV-UACIII?IE AIN 
       ?IIIUE IO?AOI?.
       o?AOEAI aIAEOAA eI?UOEIO.


eUIAIAIEN ? nginx 0.4.7                                           10.10.2006

    *) aIAA?IAIEA: IIAOIO ngx_http_flv_module.

    *) aIAA?IAIEA: ?AOAIAIIAN $request_body_file.

    *) aIAA?IAIEA: AEOAEOE?U charset E source_charset ?IAAAOOE?AAO 
       ?AOAIAIIUA.

    *) eO?OA?IAIEA: AOIE AI EIIAIAU SSI include O ?AOAIAOOII wait 
       ?U?IIINIAOO AY? IAIA EIIAIAA SSI include, OI ?AOAIAOO wait IIC IA 
       OAAIOAOO.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AEOAEOE?U "proxy_buffering off" EIE 
       ?OE OAAIOA O memcached OIAAEIAIEN IICIE IA UAEOU?AOOON ?I OAEIAOOO.

    *) eO?OA?IAIEA: nginx IA UA?OOEAION IA 64-AEOIUE ?IAO?IOIAE, IOIE?IUE 
       IO amd64, sparc64 E ppc64.


eUIAIAIEN ? nginx 0.4.6                                           06.10.2006

    *) eO?OA?IAIEA: nginx IA UA?OOEAION IA 64-AEOIUE ?IAO?IOIAE, IOIE?IUE 
       IO amd64, sparc64 E ppc64.

    *) eO?OA?IAIEA: ?OE UA?OIOA ?AOOEE HTTP/1.1 nginx ?AOAAA?AI IO?AO 
       chunk'AIE, AOIE AIEIA IO?AOA ? IAOIAA 
       $r->headers_out("Content-Length", ...) AUIA UAAAIA OAEOOI?IE OOOIEIE.

    *) eO?OA?IAIEA: ?IOIA ?AOAIA?OA?IAIEN IUEAEE O ?IIIYOA AEOAEOE?U 
       error_page IAAAN AEOAEOE?A IIAOIN ngx_http_rewrite_module ?IU?OAYAIA 
       UOO IUEAEO; IUEAEA ?IN?EIAOO ? 0.4.4.


eUIAIAIEN ? nginx 0.4.5                                           02.10.2006

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA Linux E Solaris; IUEAEA ?IN?EIAOO 
       ? 0.4.4.


eUIAIAIEN ? nginx 0.4.4                                           02.10.2006

    *) aIAA?IAIEA: ?AOAIAIIAN $scheme.

    *) aIAA?IAIEA: AEOAEOE?A expires ?IAAAOOE?AAO ?AOAIAOO max.

    *) aIAA?IAIEA: AEOAEOE?A include ?IAAAOOE?AAO IAOEO "*".
       o?AOEAI Jonathan Dance.

    *) eO?OA?IAIEA: AEOAEOE?A return ?OACAA EUIAINIA EIA IO?AOA, 
       ?AOAIA?OA?IAIIICI AEOAEOE?IE error_page.

    *) eO?OA?IAIEA: ?OIEOEIAEI segmentation fault, AOIE ? IAOIAA PUT 
       ?AOAAA?AIIOO OAII IOIA?IE AIEIU.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?AOAIAIIUE ? AEOAEOE?A proxy_redirect 
       OAAEOAEO EUIAINION IA?AOII.


eUIAIAIEN ? nginx 0.4.3                                           26.09.2006

    *) eUIAIAIEA: IUEAEO 499 OA?AOO IAIOUN ?AOAIA?OA?EOO O ?IIIYOA 
       AEOAEOE?U error_page.

    *) aIAA?IAIEA: ?IAAAOOEA Solaris 10 event ports.

    *) aIAA?IAIEA: IIAOIO ngx_http_browser_module.

    *) eO?OA?IAIEA: ?OE ?AOAIA?OA?IAIEE IUEAEE 400 ?OIEOEOI?AIIIIO OAO?AOO 
       ?IIIYOA AEOAEOE?U error_page IIC ?OIEUIEOE segmentation fault.

    *) eO?OA?IAIEA: ?OIEOEIAEI segmentation fault, AOIE ? AEOAEOE?A 
       proxy_pass EO?IIOUI?AION unix domain OIEAO; IUEAEA ?IN?EIAOO ? 
       0.3.47.

    *) eO?OA?IAIEA: SSI IA OAAIOAI O IO?AOAIE memcached E 
       IAAO?AOEUEOI?AIIUIE ?OIEOEOI?AIIUIE IO?AOAIE.

    *) eUIAIAIEA: IAEIA IUEAEE PAUSE hardware capability ? Sun Studio.


eUIAIAIEN ? nginx 0.4.2                                           14.09.2006

    *) eO?OA?IAIEA: OAOAIA ?IAAAOOEA ?IACA O_NOATIME IA Linux; IUEAEA 
       ?IN?EIAOO ? 0.4.1.


eUIAIAIEN ? nginx 0.4.1                                           14.09.2006

    *) eO?OA?IAIEA: OI?IAOOEIIOOO O DragonFlyBSD.
       o?AOEAI ?A?IO iAUAOI?O.

    *) eUIAIAIEA: IAEIA IUEAEE ? sendfile() ? 64-AEOIII Linux ?OE ?AOAAA?A 
       ?AEII? AIIOUA 2G.

    *) aIAA?IAIEA: OA?AOO IA Linux nginx AIN OOAOE?AOEEE UA?OIOI? 
       EO?IIOUOAO ?IAC O_NOATIME.
       o?AOEAI Yusuf Goolamabbas.


eUIAIAIEN ? nginx 0.4.0                                           30.08.2006

    *) eUIAIAIEA ?I ?IOOOAIIAI API: EIEAEAIEUAAEN IIAOIAE HTTP ?AOAIAOAIA 
       EU ?AUU init module ? ?AUO HTTP postconfiguration.

    *) eUIAIAIEA: OA?AOO OAII UA?OIOA ? IIAOIA ngx_http_perl_module IA 
       O?EOU?AAOON UAOAIAA: IOOII N?II EIEAEEOI?AOO ?OAIEA O ?IIIYOA IAOIAA 
       $r->has_request_body.

    *) aIAA?IAIEA: IIAOIO ngx_http_perl_module ?IAAAOOE?AAO EIA ?IU?OAOA 
       DECLINED.

    *) aIAA?IAIEA: IIAOIO ngx_http_dav_module ?IAAAOOE?AAO ?EIANYOA OOOIEO 
       UACIII?EA "Date" AIN IAOIAA PUT.

    *) aIAA?IAIEA: AEOAEOE?A ssi OAAIOAAO ?IOOOE AIIEA if.

    *) eO?OA?IAIEA: ?OIEOEIAEI segmentation fault, AOIE ? AEOAEOE?A index 
       EO?IIOUI?AIAOO ?AOAIAIIUA E ?OE UOII ?AO?IA EIN EIAAEOIICI ?AEIA 
       AUII AAU ?AOAIAIIUE; IUEAEA ?IN?EIAOO ? 0.1.29.


eUIAIAIEN ? nginx 0.3.61                                          28.08.2006

    *) eUIAIAIEA: AEOAEOE?A tcp_nodelay OA?AOO ?I OIII?AIEA ?EIA?AIA.

    *) aIAA?IAIEA: AEOAEOE?A msie_refresh.

    *) aIAA?IAIEA: AEOAEOE?A recursive_error_pages.

    *) eO?OA?IAIEA: AEOAEOE?A rewrite ?IU?OAYAIA IA?OA?EIOIUE OAAEOAEO, 
       AOIE OAAEOAEO ?EIA?AI ? OAAN ?UAAIAIIUA UAEIAEOI?AIIUA OEI?IIU EU 
       IOECEIAIOIICI URI.


eUIAIAIEN ? nginx 0.3.60                                          18.08.2006

    *) eO?OA?IAIEA: ?I ?OAIN ?AOAIA?OA?IAIEN IUEAEE OAAI?EE ?OIAAOO IIC 
       UAAEEIEOOON; IUEAEA ?IN?EIAOO ? 0.3.59.


eUIAIAIEN ? nginx 0.3.59                                          16.08.2006

    *) aIAA?IAIEA: OA?AOO IIOII AAIAOO IAOEIIOEI ?AOAIA?OA?IAIEE ?AOAU 
       AEOAEOE?O error_page.

    *) eO?OA?IAIEA: AEOAEOE?A dav_access IA ?IAAAOOE?AIA OOE ?AOAIAOOA.

    *) eO?OA?IAIEA: AEOAEOE?A error_page IA EUIAINIA OOOIEO "Content-Type" 
       ?IOIA ?AOAIA?OA?IAIEN O ?IIIYOA "X-Accel-Redirect"; IUEAEA ?IN?EIAOO 
       ? 0.3.58.


eUIAIAIEN ? nginx 0.3.58                                          14.08.2006

    *) aIAA?IAIEA: AEOAEOE?A error_page ?IAAAOOE?AAO ?AOAIAIIUA.

    *) eUIAIAIEA: OA?AOO IA Linux EO?IIOUOAOON EIOAO?AEO procfs ?IAOOI 
       sysctl.

    *) eUIAIAIEA: OA?AOO ?OE EO?IIOUI?AIEE "X-Accel-Redirect" OOOIEA 
       "Content-Type" IAOIAAOAOON EU ?AO?IIA?AIOIICI IO?AOA.

    *) eO?OA?IAIEA: AEOAEOE?A error_page IA ?AOAIA?OA?INIA IUEAEO 413.

    *) eO?OA?IAIEA: UA?AOUAAYEE "?" IA OAAINI OOAOUA AOCOIAIOU, AOIE ? 
       ?AOA?EOAIIII URI IA AUII II?UE AOCOIAIOI?.

    *) eO?OA?IAIEA: nginx IA UA?OOEAION IA 64-AEOIIE FreeBSD 7.0-CURRENT.


eUIAIAIEN ? nginx 0.3.57                                          09.08.2006

    *) aIAA?IAIEA: ?AOAIAIIAN $ssl_client_serial.

    *) eO?OA?IAIEA: ? I?AOAOIOA "!-e" ? AEOAEOE?A if.
       o?AOEAI aIAOEAIO aOAAIAI?O.

    *) eO?OA?IAIEA: ?OE ?OI?AOEA EIEAIOOEICI OAOOE?EEAOA nginx IA ?AOAAA?AI 
       EIEAIOO EI?IOIAAEA I OOAAOAIUE OAOOE?EEAOAE.

    *) eO?OA?IAIEA: ?AOAIAIIAN $document_root IA ?IAAAOOE?AIA ?AOAIAIIUA ? 
       AEOAEOE?A root.


eUIAIAIEN ? nginx 0.3.56                                          04.08.2006

    *) aIAA?IAIEA: AEOAEOE?A dav_access.

    *) aIAA?IAIEA: AEOAEOE?A if ?IAAAOOE?AAO I?AOAOIOU "-d", "!-d", "-e", 
       "!-e", "-x" E "!-x".

    *) eO?OA?IAIEA: ?OE UA?EOE ? access_log IAEIOIOUE ?AOAAA?AAIUE EIEAIOO 
       OOOIE UACIII?EI? ?OIEOEIAEI segmentation fault, AOIE UA?OIO 
       ?IU?OAYAI OAAEOAEO.


eUIAIAIEN ? nginx 0.3.55                                          28.07.2006

    *) aIAA?IAIEA: ?AOAIAOO stub ? EIIAIAA SSI include.

    *) aIAA?IAIEA: EIIAIAA SSI block.

    *) aIAA?IAIEA: OEOE?O unicode2nginx AIAA?IAI ? contrib.

    *) eO?OA?IAIEA: AOIE root AUI UAAAI OIIOEI ?AOAIAIIIE, OI EIOAIO 
       UAAA?AION IOIIOEOAIOII ?OA?EEOA OAO?AOA.

    *) eO?OA?IAIEA: AOIE ? UA?OIOA AUI "//" EIE "/.", E ?IOIA UOICI 
       UAEIAEOI?AIIUA OEI?IIU ? ?EAA "%XX", OI ?OIEOEOOAIUE UA?OIO 
       ?AOAAA?AION IAUAEIAEOI?AIIUI.

    *) eO?OA?IAIEA: IAOIA $r->header_in("Cookie") IIAOIN 
       ngx_http_perl_module OA?AOO ?IU?OAYAAO ?OA OOOIEE "Cookie" ? 
       UACIII?EA UA?OIOA.

    *) eO?OA?IAIEA: ?OIEOEIAEI segmentation fault, AOIE EO?IIOUI?AION 
       "client_body_in_file_only on" E AAIAION ?AOAEIA E OIAAOAYAIO AUEAIAO.

    *) eO?OA?IAIEA: ?OE IAEIOIOUE OOII?ENE ?I ?OAIN ?AOAEII?ECOOAAEE EIAU 
       OEI?III? ?IOOOE AEOAEOE?U charset_map IICIE O?EOAOOON IA?AOIUIE; 
       IUEAEA ?IN?EIAOO ? 0.3.50.


eUIAIAIEN ? nginx 0.3.54                                          11.07.2006

    *) aIAA?IAIEA: nginx OA?AOO UA?EOU?AAO ? IIC EI?IOIAAEA I ?IAUA?OIOAE.

    *) aIAA?IAIEA: AEOAEOE?U proxy_next_upstream, fastcgi_next_upstream E 
       memcached_next_upstream ?IAAAOOE?AAO ?AOAIAOO off.

    *) aIAA?IAIEA: AEOAEOE?A debug_connection ?IAAAOOE?AAO UA?EOO AAOAOI? ? 
       ?IOIAOA CIDR.

    *) eO?OA?IAIEA: ?OE ?AOAEIAEOI?AIEE IO?AOA ?OIEOEOI?AIIICI OAO?AOA EIE 
       OAO?AOA FastCGI ? UTF-8 EIE IAIAIOIO IO?AO IIC ?AOAAA?AOOON IA 
       ?IIIIOOOA.

    *) eO?OA?IAIEA: ?AOAIAIIAN $upstream_response_time OIAAOOAIA ?OAIN 
       OIIOEI ?AO?ICI IAOAYAIEN E AUEAIAO.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA ?IAO?IOIA amd64; IUEAEA ?IN?EIAOO 
       ? 0.3.53.


eUIAIAIEN ? nginx 0.3.53                                          07.07.2006

    *) eUIAIAIEA: AEOAEOE?A add_header AIAA?INAO OOOIEE ? IO?AOU O EIAII 
       204, 301 E 302.

    *) aIAA?IAIEA: AEOAEOE?A server ? AIIEA upstream ?IAAAOOE?AAO ?AOAIAOO 
       weight.

    *) aIAA?IAIEA: AEOAEOE?A server_name ?IAAAOOE?AAO IAOEO "*".

    *) aIAA?IAIEA: nginx ?IAAAOOE?AAO OAII UA?OIOA AIIOUA 2G.

    *) eO?OA?IAIEA: AOIE ?OE EO?IIOUI?AIEE "satisfy_any on" EIEAIO OO?AUII 
       ?OIEIAEI AOOAIOE?EEAAEA, ? IIC ?O? OA?II UA?EOAIIcO OIIAYAIEA 
       "access forbidden by rule".

    *) eO?OA?IAIEA: IAOIA PUT IIC IUEAI?II IA OIUAAOO ?AEI E ?AOIOOO EIA 
       409.

    *) eO?OA?IAIEA: AOIE ?I ?OAIN AOOAIOE?EEAAEE IMAP/POP3 AUEAIA ?IU?OAYAI 
       IUEAEO, nginx ?OIAIIOAI ?OIEOEOI?AIEA.


eUIAIAIEN ? nginx 0.3.52                                          03.07.2006

    *) eUIAIAIEA: ?IOOOAII?IAII ?I?AAAIEA IIAOIN ngx_http_index_module AIN 
       UA?OIOI? "POST /": EAE ? ?AOOEE AI 0.3.40, IIAOIO OA?AOO IA ?UAA?O 
       IUEAEO 405.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ICOAIE?AIEN OEIOIOOE OAAI?EE ?OIAAOO 
       IIC UAAEEIEOOON; IUEAEA ?IN?EIAOO ? 0.3.37.

    *) eO?OA?IAIEA: IIAOIO ngx_http_charset_module UA?EOU?AI ? IIC IUEAEO 
       "unknown charset", AAOA AOIE ?AOAEIAEOI?EA IA OOAAI?AIAOO; IUEAEA 
       ?IN?EIAOO ? 0.3.50.

    *) eO?OA?IAIEA: AOIE ? OAUOIOOAOA UA?OIOA PUT ?IU?OAYAION EIA 409, OI 
       ?OAIAIIUE ?AEI IA OAAINION.


eUIAIAIEN ? nginx 0.3.51                                          30.06.2006

    *) eO?OA?IAIEA: ?OE IAEIOIOUE OOII?ENE ? SSI IIC ?OI?AAAOO OEI?IIU "<"; 
       IUEAEA ?IN?EIAOO ? 0.3.50.


eUIAIAIEN ? nginx 0.3.50                                          28.06.2006

    *) eUIAIAIEA: AEOAEOE?U proxy_redirect_errors E fastcgi_redirect_errors 
       ?AOAEIAII?AIU OIIO?AOOO?AIII ? proxy_intercept_errors E 
       fastcgi_intercept_errors.

    *) aIAA?IAIEA: IIAOIO ngx_http_charset_module ?IAAAOOE?AAO 
       ?AOAEIAEOI?AIEA EU IAIIAAEOIUE EIAEOI?IE ? UTF-8 E IAOAOII.

    *) aIAA?IAIEA: ? OAOEIA ?OIEOE E FastCGI ?IAAAOOE?AAOON OOOIEA 
       UACIII?EA "X-Accel-Charset" ? IO?AOA AUEAIAA.

    *) eO?OA?IAIEA: OEI?II "\" ? ?AOAE "\"" E "\'" ? SSI EIIAIAAE OAEOAION, 
       OIIOEI AOIE OAEOA EO?IIOUI?AION OEI?II "$".

    *) eO?OA?IAIEA: ?OE IAEIOIOUE OOII?ENE ? SSI ?IOIA ?OOA?EE IICIA AUOO 
       AIAA?IAIA OOOIEA "<!--".

    *) eO?OA?IAIEA: AOIE ? UACIII?EA IO?AOA AUIA OOOIEA 
       "Content-Length: 0", OI ?OE EO?IIOUI?AIEE IAAO?AOEUEOI?AIIICI 
       ?OIEOEOI?AIEE IA UAEOU?AIIOO OIAAEIAIEA O EIEAIOII.


eUIAIAIEN ? nginx 0.3.49                                          31.05.2006

    *) eO?OA?IAIEA: ? AEOAEOE?A set.

    *) eO?OA?IAIEA: ?OE ?EIA?AIEE ? ssi A?OE E AIIAA ?IAUA?OIOI?, 
       IAOAAAOU?AAIUE ?AOAU FastCGI, ?IAOOI ?U?IAA ?OIOICI E IOOAIOIUE 
       ?IAUA?OIOI? ? IO?AO ?EIA?AION ?U?IA ?AO?ICI ?IAUA?OIOA.


eUIAIAIEN ? nginx 0.3.48                                          29.05.2006

    *) eUIAIAIEA: OA?AOO IIAOIO ngx_http_charset_module OAAIOAAO AIN 
       ?IAUA?OIOI?, ? IO?AOAE EIOIOUE IAO OOOIEE UACIII?EA "Content-Type".

    *) eO?OA?IAIEA: AOIE ? AEOAEOE?A proxy_pass IA AUII URI, OI AEOAEOE?A 
       "proxy_redirect default" AIAA?INIA ? ?AOA?EOAIIUE OAAEOAEO ? IA?AII 
       IEUIEE OIUU.

    *) eO?OA?IAIEA: ?IOOOAIIEE OAAEOAEO ?OACAA ?OA?OAYAI IAAIE HTTP-IAOIA ? 
       GET, OA?AOO UOI AAIAAOON OIIOEI AIN OAAEOAEOI?, ?U?IIINAIUE O 
       ?IIIYOA X-Accel-Redirect, E O EIOIOUE IAOIA IA OA?AI HEAD; IUEAEA 
       ?IN?EIAOO ? 0.3.42.

    *) eO?OA?IAIEA: IIAOIO ngx_http_perl_module IA OIAEOAION, AOIE ?AOI AUI 
       O ?IAAAOOEIE ?IOIEI?; IUEAEA ?IN?EIAOO ? 0.3.46.


eUIAIAIEN ? nginx 0.3.47                                          23.05.2006

    *) aIAA?IAIEA: AEOAEOE?A upstream.

    *) eUIAIAIEA: OEI?II "\" ? ?AOAE "\"" E "\'" ? SSI EIIAIAAE OA?AOO 
       ?OACAA OAEOAAOON.


eUIAIAIEN ? nginx 0.3.46                                          11.05.2006

    *) aIAA?IAIEA: AEOAEOE?U proxy_hide_header, proxy_pass_header, 
       fastcgi_hide_header E fastcgi_pass_header.

    *) eUIAIAIEA: AEOAEOE?U proxy_pass_x_powered_by, fastcgi_x_powered_by E 
       proxy_pass_server O?OAUAIAIU.

    *) aIAA?IAIEA: ? OAOEIA ?OIEOE ?IAAAOOE?AAOON OOOIEA UACIII?EA 
       "X-Accel-Buffering" ? IO?AOA AUEAIAA.

    *) eO?OA?IAIEA: IUEAIE E OOA?AE ?AINOE ?OE ?AOAEII?ECOOAAEE ? IIAOIA 
       ngx_http_perl_module.


eUIAIAIEN ? nginx 0.3.45                                          06.05.2006

    *) aIAA?IAIEA: AEOAEOE?U ssl_verify_client, ssl_verify_depth E 
       ssl_client_certificate.

    *) eUIAIAIEA: OA?AOO ?AOAIAIIAN $request_method ?IU?OAYAAO IAOIA OIIOEI 
       IOII?IICI UA?OIOA.

    *) eUIAIAIEA: ? OAAIEAA ?AOAEIAEOI?EE koi-win EUIAIAIU EIAU OEI?IIA 
       &deg;.

    *) aIAA?IAIEA: ? OAAIEAO ?AOAEIAEOI?EE koi-win AIAA?IAIU OEI?IIU A?OI E 
       IIIAOA.

    *) eO?OA?IAIEA: AOIE nginx OAO?OAAAINI UA?OIOU IA IAOEIIOEI IAUEI, OI 
       ?OE ?AAAIEE IAIIE EU IEE UA?OIOU, ?OAAIAUIA?AIIUA AIN UOIE IAUEIU, 
       ?AOAIA?OA?INIEOO OIIOEI IA IAIO IAUEIO ?IAOOI OICI, ?OIAU OA?IIIAOII 
       OAO?OAAAINOOON IAOAO IOOAIOIUIE.


eUIAIAIEN ? nginx 0.3.44                                          04.05.2006

    *) aIAA?IAIEA: ?AOAIAOO wait ? EIIAIAA SSI include.

    *) aIAA?IAIEA: ? OAAIEAO ?AOAEIAEOI?EE koi-win AIAA?IAIU OEOAEIOEEA E 
       AAIIOOOOEEA OEI?IIU.

    *) eO?OA?IAIEA: ? SSI.


eUIAIAIEN ? nginx 0.3.43                                          26.04.2006

    *) eO?OA?IAIEA: ? SSI.


eUIAIAIEN ? nginx 0.3.42                                          26.04.2006

    *) aIAA?IAIEA: ?AOAIAOO bind ? AEOAEOE?A listen ? IMAP/POP3 ?OIEOE.

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE ? AEOAEOE?A rewrite IAIICI E 
       OICI OA ?UAAIAIEN AIIAA IAIICI OAUA.

    *) eO?OA?IAIEA: ? IIC IA UA?EOU?AIEOO ?AOAIAIIUA 
       $sent_http_content_type, $sent_http_content_length, 
       $sent_http_last_modified, $sent_http_connection, 
       $sent_http_keep_alive E $sent_http_transfer_encoding.

    *) eO?OA?IAIEA: ?AOAIAIIAN $sent_http_cache_control ?IU?OAYAIA 
       OIAAOOEIIA OIIOEI IAIIE OOOIEE "Cache-Control" ? UACIII?EA IO?AOA.


eUIAIAIEN ? nginx 0.3.41                                          21.04.2006

    *) aIAA?IAIEA: EIA? -v.

    *) eO?OA?IAIEA: ?OE ?EIA?AIEE ? SSI OAAI?IIUE ?IAUA?OIOI? IIC ?OIEUIEOE 
       segmentation fault.

    *) eO?OA?IAIEA: ? IAOAAIOEA FastCGI.

    *) eO?OA?IAIEA: AOIE ?OOO E ?AOII?UI IIAOINI IA AUI OEAUAI O ?IIIYOA 
       --with-perl_modules_path=PATH EIE AEOAEOE?U perl_modules, OI IA 
       OOAOOA ?OIEOEIAEI segmentation fault.


eUIAIAIEN ? nginx 0.3.40                                          19.04.2006

    *) aIAA?IAIEA: IIAOIO ngx_http_dav_module ?IAAAOOE?AAO IAOIA MKCOL.

    *) aIAA?IAIEA: AEOAEOE?A create_full_put_path.

    *) aIAA?IAIEA: ?AOAIAIIAN $limit_rate.


eUIAIAIEN ? nginx 0.3.39                                          17.04.2006

    *) aIAA?IAIEA: AEOAEOE?A uninitialized_variable_warn; OOI?AIO 
       IICCEOI?AIEN OIIAYAIEN I IAEIEAEAIEUEOI?AIIIE ?AOAIAIIIE ?IIEOAI O 
       OOI?IN alert IA warn.

    *) aIAA?IAIEA: AEOAEOE?A override_charset.

    *) eUIAIAIEA: ?OE EO?IIOUI?AIEE IAEU?AOOIIE ?AOAIAIIIE ? SSI-EIIAIAAE 
       echo E if expr='$name' OA?AOO IA UA?EOU?AAOON ? IIC OIIAYAIEA I 
       IAEU?AOOIIE ?AOAIAIIIE.

    *) eO?OA?IAIEA: O??O?EE AEOE?IUE OIAAEIAIEE OIO ?OE ?OA?UUAIEE IEIEOA 
       OIAAEIAIEE, UAAAIIICI AEOAEOE?IE worker_connections; IUEAEA 
       ?IN?EIAOO ? 0.2.0.

    *) eO?OA?IAIEA: ?OE IAEIOIOUE OOII?EN ICOAIE?AIEA OEIOIOOE OIAAEIAIEN 
       IICII IA OAAIOAOO; IUEAEA ?IN?EIAOO ? 0.3.38.


eUIAIAIEN ? nginx 0.3.38                                          14.04.2006

    *) aIAA?IAIEA: IIAOIO ngx_http_dav_module.

    *) eUIAIAIEA: I?OEIEUAAEN IIAOIN ngx_http_perl_module.
       o?AOEAI oAOCAA oE?IOAI?O.

    *) aIAA?IAIEA: IIAOIO ngx_http_perl_module ?IAAAOOE?AAO IAOIA 
       $r->request_body_file.

    *) aIAA?IAIEA: AEOAEOE?A client_body_in_file_only.

    *) eUIAIAIEA: OA?AOO ?OE ?AOA?IIIAIEE AEOEA nginx ?UOAAOON ?EOAOO 
       access_log'E OIIOEI OAU ? OAEOIAO.
       o?AOEAI aIOIIO aOAIEII?O E iAEOEIO aOIEIO.

    *) eO?OA?IAIEA: OA?AOO AEOAEOE?A limit_rate OI?IAA ICOAIE?E?AAO 
       OEIOIOOO ?OE UIA?AIENE AIIOUA 100 Kbyte/s.
       o?AOEAI ForJest.

    *) eO?OA?IAIEA: IMAP/POP3 ?OIEOE OA?AOO ?AOAAA?O OAO?AOO A?OIOEUAAEE 
       OEI?IIU "\r" E "\n" ? IICEIA E ?AOIIA ? UAEIAEOI?AIIII ?EAA.
       o?AOEAI iAEOEIO aOIEIO.


eUIAIAIEN ? nginx 0.3.37                                          07.04.2006

    *) aIAA?IAIEA: AEOAEOE?A limit_except.

    *) aIAA?IAIEA: AEOAEOE?A if ?IAAAOOE?AAO I?AOAOIOU "!~", "!~*", "-f" E 
       "!-f".

    *) aIAA?IAIEA: IIAOIO ngx_http_perl_module ?IAAAOOE?AAO IAOIA 
       $r->request_body.

    *) eO?OA?IAIEA: ? IIAOIA ngx_http_addition_filter_module.


eUIAIAIEN ? nginx 0.3.36                                          05.04.2006

    *) aIAA?IAIEA: IIAOIO ngx_http_addition_filter_module.

    *) aIAA?IAIEA: AEOAEOE?U proxy_pass E fastcgi_pass IIOII EO?IIOUI?AOO 
       ?IOOOE AIIEA if.

    *) aIAA?IAIEA: AEOAEOE?U proxy_ignore_client_abort E 
       fastcgi_ignore_client_abort.

    *) aIAA?IAIEA: ?AOAIAIIAN $request_completion.

    *) aIAA?IAIEA: IIAOIO ngx_http_perl_module ?IAAAOOE?AAO IAOIAU 
       $r->request_method E $r->remote_addr.

    *) aIAA?IAIEA: IIAOIO ngx_http_ssi_module ?IAAAOOE?AAO EIIAIAO elif.

    *) eO?OA?IAIEA: OOOIEA "\/" ? IA?AIA ?UOAOAIEN EIIAIAU if IIAOIN 
       ngx_http_ssi_module ?IO?OEIEIAIAOO IA?AOII.

    *) eO?OA?IAIEA: ? EO?IIOUI?AIEE OACOINOIUE ?UOAOAIENE ? EIIAIAA if 
       IIAOIN ngx_http_ssi_module.

    *) eO?OA?IAIEA: ?OE UAAAIEE IOIIOEOAIOIICI ?OOE ? AEOAEOE?AE 
       client_body_temp_path, proxy_temp_path, fastcgi_temp_path E 
       perl_modules EO?IIOUI?AION EAOAIIC IOIIOEOAIOII OAEOYACI EAOAIICA, A 
       IA IOIIOEOAIOII ?OA?EEOA OAO?AOA.


eUIAIAIEN ? nginx 0.3.35                                          22.03.2006

    *) eO?OA?IAIEA: accept-?EIOOO E TCP_DEFER_ACCEPT OOOAIA?IE?AIEOO OIIOEI 
       AIN ?AO?IE AEOAEOE?U listen; IUEAEA ?IN?EIAOO ? 0.3.31.

    *) eO?OA?IAIEA: ? AEOAEOE?A proxy_pass AAU URI ?OE EO?IIOUI?AIEE ? 
       ?IAUA?OIOA.


eUIAIAIEN ? nginx 0.3.34                                          21.03.2006

    *) aIAA?IAIEA: AEOAEOE?A add_header ?IAAAOOE?AAO ?AOAIAIIUA.


eUIAIAIEN ? nginx 0.3.33                                          15.03.2006

    *) aIAA?IAIEA: ?AOAIAOO http_503 ? AEOAEOE?AE proxy_next_upstream EIE 
       fastcgi_next_upstream.

    *) eO?OA?IAIEA: ngx_http_perl_module IA OAAIOAI OI ?OOOIAIIUI ? 
       EII?ECOOAAEIIIUE ?AEI EIAII, AOIE II IA IA?EIAION OOAUO OA O "sub".

    *) eO?OA?IAIEA: ? AEOAEOE?A post_action.


eUIAIAIEN ? nginx 0.3.32                                          11.03.2006

    *) eO?OA?IAIEA: OAAIAIEA IOIAAI?IICI IICCEOI?AIEN IA OOAOOA E ?OE 
       ?AOAEII?ECOOAAEE; IUEAEA ?IN?EIAOO ? 0.3.31.


eUIAIAIEN ? nginx 0.3.31                                          10.03.2006

    *) eUIAIAIEA: OA?AOO nginx ?AOAAA?O IA?AOIUA IO?AOU ?OIEOEOI?AIIICI 
       AUEAIAA.

    *) aIAA?IAIEA: AEOAEOE?U listen ?IAAAOOE?AAO AAOAO ? ?EAA "*:?IOO".

    *) aIAA?IAIEA: ?IAAAOOEA EVFILER_TIMER ? MacOSX 10.4.

    *) eUIAIAIEA: IAEIA IUEAEE IAOAAIOEE IEIIEOAEOIAIUE OAEIAOOI? kqueue ? 
       64-AEOIII NAOA MacOSX.
       o?AOEAI aIAOAA iECIAOOIEIO.

    *) eO?OA?IAIEA: AOIE ?IOOOE IAIICI OAO?AOA I?EOAIU IAOEIIOEI AEOAEOE? 
       listen, OIOUAAYEE IA OAUIUE AAOAOAE, OI EIAIA OAO?AOI? ?EAA 
       "*.domain.tld" OAAIOAIE OIIOEI AIN ?AO?ICI AAOAOA; IUEAEA ?IN?EIAOO 
       ? 0.3.18.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?OIOIEIIA HTTPS ? AEOAEOE?A 
       proxy_pass IA ?AOAAA?AIEOO UA?OIOU O OAIII, UA?EOAIIUI ?I ?OAIAIIUE 
       ?AEI.

    *) eO?OA?IAIEA: OI?IAOOEIIOOO O perl 5.8.8.


eUIAIAIEN ? nginx 0.3.30                                          22.02.2006

    *) eUIAIAIEA: OOI?AIO UA?EOE ? IIC IUEAEE ECONNABORTED EUIAI?I IA error 
       O OOI?IN crit.

    *) eO?OA?IAIEA: IIAOIO ngx_http_perl_module IA OIAEOAION AAU IIAOIN 
       ngx_http_ssi_filter_module.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA i386 ?IAO?IOIA, AOIE 
       EO?IIOUI?AION PIC; IUEAEA ?IN?EIAOO ? 0.3.27.


eUIAIAIEN ? nginx 0.3.29                                          20.02.2006

    *) aIAA?IAIEA: OA?AOO nginx EO?IIOUOAO IAIOUA ?AINOE, AOIE PHP ? OAOEIA 
       FastCGI ?AOAAA?O AIIOUIA EIIE?AOO?I ?OAAO?OAOAAIEE ?AOAA IO?AOII.

    *) eO?OA?IAIEA: ? IO?AOAE 204 AIN UA?OIOI? ?AOOEE HTTP/1.1 ?UAA?AIAOO 
       OOOIEA UACIII?EA "Transfer-Encoding: chunked".

    *) eO?OA?IAIEA: nginx ?IU?OAYAI 502 EIA IO?AOA, AOIE FastCGI OAO?AO 
       ?AOAAA?AI ?IIIUA OOOIEE UACIII?EA IO?AOA ? IOAAIOIUE FastCGI UA?EONE.

    *) eO?OA?IAIEA: AOIE ? AEOAEOE?A post_action AUI OEAUAI ?OIEOEOOAIUE 
       URI, OI II ?U?IIINION OIIOEI ?IOIA OO?AUIICI UA?AOUAIEN UA?OIOA.


eUIAIAIEN ? nginx 0.3.28                                          16.02.2006

    *) aIAA?IAIEA: AEOAEOE?A restrict_host_names O?OAUAIAIA.

    *) aIAA?IAIEA: ?AOAIAOO EII?ECOOAAEE --with-cpu-opt=ppc64.

    *) eO?OA?IAIEA: ?OE IAEIOIOUE OOII?ENE ?OIEOEOI?AIIIA OIAAEIAIEA O 
       EIEAIOII UA?AOUAIIOO ?OAOAA?OAIAIII.
       o?AOEAI ?IAAEIEOO uOOI?O.

    *) eO?OA?IAIEA: OOOIEA UACIII?EA "X-Accel-Limit-Rate" IA O?EOU?AIAOO 
       AIN UA?OIOI?, ?AOAIA?OA?IAIIUE O ?IIIYOA OOOIEE "X-Accel-Redirect".

    *) eO?OA?IAIEA: AEOAEOE?A post_action OAAIOAIA OIIOEI ?IOIA OO?AUIICI 
       UA?AOUAIEN UA?OIOA.

    *) eO?OA?IAIEA: OAII ?OIEOEOI?AIIICI IO?AOA, OIUAA?AAIICI AEOAEOE?IE 
       post_action, ?AOAAA?AIIOO EIEAIOO.


eUIAIAIEN ? nginx 0.3.27                                          08.02.2006

    *) eUIAIAIEA: AEOAEOE?U variables_hash_max_size E 
       variables_hash_bucket_size.

    *) aIAA?IAIEA: ?AOAIAIIAN $body_bytes_sent AIOOO?IA IA OIIOEI ? 
       AEOAEOE?A log_format.

    *) aIAA?IAIEA: ?AOAIAIIUA $ssl_protocol E $ssl_cipher.

    *) aIAA?IAIEA: I?OAAAIAIEA OAUIAOA OOOIEE EUUA OAO?OIOOOAI?IIUE 
       ?OIAAOOIOI? ?OE OOAOOA.

    *) aIAA?IAIEA: AEOAEOE?A accept_mutex OA?AOO ?IAAAOOE?AAOON ?IOOAAOO?II 
       fcntl(2) IA ?IAO?IOIAE, IOIE?IUE IO i386, amd64, sparc64 E ppc.

    *) aIAA?IAIEA: AEOAEOE?A lock_file E ?AOAIAOO A?OIEII?ECOOAAEE 
       --with-lock-path=PATH.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?OIOIEIIA HTTPS ? AEOAEOE?A 
       proxy_pass IA ?AOAAA?AIEOO UA?OIOU O OAIII.


eUIAIAIEN ? nginx 0.3.26                                          03.02.2006

    *) eUIAIAIEA: AEOAEOE?A optimize_host_names ?AOAEIAII?AIA ? 
       optimize_server_names.

    *) eO?OA?IAIEA: ?OE ?OIEOEOI?AIEE ?IAUA?OIOA ? SSI AUEAIAO ?AOAAA?AION 
       URI IOII?IICI UA?OIOA, AOIE ? AEOAEOE?A proxy_pass IOOOOOO?I?AI URI.


eUIAIAIEN ? nginx 0.3.25                                          01.02.2006

    *) eO?OA?IAIEA: ?OE IA?AOIIE EII?ECOOAAEE IA OOAOOA EIE ?I ?OAIN 
       ?AOAEII?ECOOAAEE ?OIEOEIAEI segmentation fault; IUEAEA ?IN?EIAOO ? 
       0.3.24.


eUIAIAIEN ? nginx 0.3.24                                          01.02.2006

    *) eUIAIAIEA: IAEIA IUEAEE ? kqueue ?I FreeBSD.

    *) eO?OA?IAIEA: IO?AO, OIUAA?AAIUE AEOAEOE?IE post_action, OA?AOO IA 
       ?AOAAA?OON EIEAIOO.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE AIIOUICI EIIE?AOO?A IIC-?AEII? 
       ?OIEOEIAEIA OOA?EA ?AINOE.

    *) eO?OA?IAIEA: ?IOOOE IAIICI location OAAIOAIA OIIOEI ?AO?AN AEOAEOE?A 
       proxy_redirect.

    *) eO?OA?IAIEA: IA 64-AEOIUE ?IAO?IOIAE ?OE OOAOOA IIC ?OIEUIEOE 
       segmentation fault, AOIE EO?IIOUI?AIIOO AIIOUIA EIIE?AOO?I EI?I ? 
       AEOAEOE?AE server_name; IUEAEA ?IN?EIAOO ? 0.3.18.


eUIAIAIEN ? nginx 0.3.23                                          24.01.2006

    *) aIAA?IAIEA: AEOAEOE?A optimize_host_names.

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE ?AOAIAIIUE ? AEOAEOE?AE path E 
       alias.

    *) eO?OA?IAIEA: IIAOIO ngx_http_perl_module IA?OA?EIOII OIAEOAION IA 
       Linux E Solaris.


eUIAIAIEN ? nginx 0.3.22                                          17.01.2006

    *) aIAA?IAIEA: IIAOIO ngx_http_perl_module ?IAAAOOE?AAO IAOIAU $r->args 
       E $r->unescape.

    *) aIAA?IAIEA: IAOIA $r->query_string ? IIAOIA ngx_http_perl_module 
       O?OAUAI?I.

    *) eO?OA?IAIEA: AOIE ? AEOAEOE?A valid_referers OEAUAIU OIIOEI none EIE 
       blocked, OI ?OIEOEIAEI segmentation fault; IUEAEA ?IN?EIAOO ? 0.3.18.


eUIAIAIEN ? nginx 0.3.21                                          16.01.2006

    *) aIAA?IAIEA: IIAOIO ngx_http_perl_module.

    *) eUIAIAIEA: AEOAEOE?A valid_referers OAUOAUAAO EO?IIOUI?AOO OA?AOAOU 
       OI?OAI AAU URI.


eUIAIAIEN ? nginx 0.3.20                                          11.01.2006

    *) eO?OA?IAIEA: IUEAEE ? IAOAAIOEA SSI.

    *) eO?OA?IAIEA: IIAOIO ngx_http_memcached_module IA ?IAAAOOE?AI EIA?E ? 
       ?EAA /uri?args.


eUIAIAIEN ? nginx 0.3.19                                          28.12.2005

    *) aIAA?IAIEA: AEOAEOE?U path E alias ?IAAAOOE?AAO ?AOAIAIIUA.

    *) eUIAIAIEA: OA?AOO AEOAEOE?A valid_referers I?NOO O?EOU?AAO URI.

    *) eO?OA?IAIEA: IUEAEE ? IAOAAIOEA SSI.


eUIAIAIEN ? nginx 0.3.18                                          26.12.2005

    *) aIAA?IAIEA: AEOAEOE?A server_names ?IAAAOOE?AAO EIAIA ?EAA 
       ".domain.tld".

    *) aIAA?IAIEA: AEOAEOE?A server_names EO?IIOUOAO EUU AIN EI?I ?EAA 
       "*.domain.tld" E AIIAA U??AEOE?IUE EUU AIN IAU?IUE EI?I.

    *) eUIAIAIEA: AEOAEOE?U server_names_hash_max_size E 
       server_names_hash_bucket_size.

    *) eUIAIAIEA: AEOAEOE?U server_names_hash E server_names_hash_threshold 
       O?OAUAIAIU.

    *) aIAA?IAIEA: AEOAEOE?A valid_referers EO?IIOUOAO EUU AIN EI?I OAEOI?.

    *) eUIAIAIEA: OA?AOO AEOAEOE?A valid_referers ?OI?AONAO OIIOEI EIAIA 
       OAEOI? AAU O??OA URI.

    *) eO?OA?IAIEA: IAEIOIOUA EIAIA ?EAA ".domain.tld" IA?AOII 
       IAOAAAOU?AIEOO IIAOIAI ngx_http_map_module.

    *) eO?OA?IAIEA: AOIE EII?ECOOAAEIIIICI ?AEIA IA AUII, OI ?OIEOEIAEI 
       segmentation fault; IUEAEA ?IN?EIAOO ? 0.3.12.

    *) eO?OA?IAIEA: IA 64-AEOIUE ?IAO?IOIAE ?OE OOAOOA IIC ?OIEUIEOE 
       segmentation fault; IUEAEA ?IN?EIAOO ? 0.3.16.


eUIAIAIEN ? nginx 0.3.17                                          18.12.2005

    *) eUIAIAIEA: IA Linux configure OA?AOO ?OI?AONAO IAIE?EA epoll E 
       sendfile64() ? NAOA.

    *) aIAA?IAIEA: AEOAEOE?A map ?IAAAOOE?AAO AIIAIIUA EIAIA ? ?IOIAOA 
       ".domain.tld".

    *) eO?OA?IAIEA: ?I ?OAIN SSL handshake IA Ec?IIOUI?AIEOO OAEIAOOU; 
       IUEAEA ?IN?EIAOO ? 0.2.4.

    *) eO?OA?IAIEA: ? EO?IIOUI?AIEE ?OIOIEIIA HTTPS ? AEOAEOE?A proxy_pass.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE ?OIOIEIIA HTTPS ? AEOAEOE?A 
       proxy_pass ?I OIII?AIEA EO?IIOUI?AION ?IOO 80.


eUIAIAIEN ? nginx 0.3.16                                          16.12.2005

    *) aIAA?IAIEA: IIAOIO ngx_http_map_module.

    *) aIAA?IAIEA: AEOAEOE?U types_hash_max_size E types_hash_bucket_size.

    *) aIAA?IAIEA: AEOAEOE?A ssi_value_length.

    *) aIAA?IAIEA: AEOAEOE?A worker_rlimit_core.

    *) eUIAIAIEA: ?OE OAIOEA EII?EINOIOAIE icc 8.1 E 9.0 O I?OEIEUAAEAE AIN 
       Pentium 4 IIIAO OIAAEIAIEN ? IICAE ?OACAA AUI OA?AI 1.

    *) eO?OA?IAIEA: EIIAIAA config timefmt ? SSI UAAA?AIA IA?AOIUE ?IOIAO 
       ?OAIAIE.

    *) eO?OA?IAIEA: nginx IA UAEOU?AI OIAAEIAIEN O IMAP/POP3 AUEAIAII ?OE 
       EO?IIOUI?AIEE SSL OIAAEIAIEE; IUEAEA ?IN?EIAOO ? 0.3.13.
       o?AOEAI Rob Mueller.

    *) eO?OA?IAIEA: segmentation fault IIC ?OIEUIEOE ?I ?OAIN SSL shutdown; 
       IUEAEA ?IN?EIAOO ? 0.3.13.


eUIAIAIEN ? nginx 0.3.15                                          07.12.2005

    *) aIAA?IAIEA: II?IE EIA 444 ? AEOAEOE?A return AIN UAEOUOEN OIAAEIAIEN.

    *) aIAA?IAIEA: AEOAEOE?A so_keepalive ? IMAP/POP3 ?OIEOE.

    *) eO?OA?IAIEA: nginx OA?AOO ?UUU?AAO abort() ?OE IAIAOOOAIEE 
       IAUAEOUOUE OIAAEIAIEE OIIOEI ?OE ?IAIII ?UEIAA E ?EIA??IIIE 
       AEOAEOE?A debug_points.


eUIAIAIEN ? nginx 0.3.14                                          05.12.2005

    *) eO?OA?IAIEA: ? IO?AOA 304 ?AOAAA?AIIOO OAII IO?AOA; IUEAEA ?IN?EIAOO 
       ? 0.3.13.


eUIAIAIEN ? nginx 0.3.13                                          05.12.2005

    *) aIAA?IAIEA: IMAP/POP3 ?OIEOE ?IAAAOOE?AAO STARTTLS E STLS.

    *) eO?OA?IAIEA: IMAP/POP3 ?OIEOE IA OAAIOAIA O IAOIAAIE select, poll E 
       /dev/poll.

    *) eO?OA?IAIEA: IUEAEE ? IAOAAIOEA SSI.

    *) eO?OA?IAIEA: sendfilev() ? Solaris OA?AOO IA EO?IIOUOAOON ?OE 
       ?AOAAA?A OAIA UA?OIOA FastCGI-OAO?AOO ?AOAU unix domain OIEAO.

    *) eO?OA?IAIEA: AEOAEOE?A auth_basic IA UA?OAYAIA AOOAIOE?EEAAEA; 
       IUEAEA ?IN?EIAOO ? 0.3.11.


eUIAIAIEN ? nginx 0.3.12                                          26.11.2005

    *) aAUI?AOIIOOO: AOIE nginx AUI OIAOAI O IIAOIAI 
       ngx_http_realip_module, OI ?OE EO?IIOUI?AIEE AEOAEOE?U "satisfy_any 
       on" AEOAEOE?U AIOOO?A E AOOAIOE?EEAAEE IA OAAIOAIE. iIAOIO 
       ngx_http_realip_module IA OIAEOAION E IA OIAEOAAOON ?I OIII?AIEA.

    *) eUIAIAIEA: EIN ?AOAIAIIIE "$time_gmt" EUIAIAII IA "$time_local".

    *) eUIAIAIEA: AEOAEOE?U proxy_header_buffer_size E 
       fastcgi_header_buffer_size ?AOAEIAII?AIU OIIO?AOOO?AIII ? 
       proxy_buffer_size E fastcgi_buffer_size.

    *) aIAA?IAIEA: IIAOIO ngx_http_memcached_module.

    *) aIAA?IAIEA: AEOAEOE?A proxy_buffering.

    *) eO?OA?IAIEA: EUIAIAIEA ? OAAIOA O accept mutex ?OE EO?IIOUI?AIEE 
       IAOIAA rtsig; IUEAEA ?IN?EIAOO ? 0.3.0.

    *) eO?OA?IAIEA: AOIE EIEAIO ?AOAAAI OOOIEO "Transfer-Encoding: chunked" 
       ? UACIII?EA UA?OIOA, OI nginx OA?AOO ?UAA?O IUEAEO 411.

    *) eO?OA?IAIEA: ?OE IAOIAAI?AIEE AEOAEOE?U auth_basic O OOI?IN http ? 
       OOOIEA "WWW-Authenticate" UACIII?EA IO?AOA ?U?IAEION realm AAU 
       OAEOOA "Basic realm".

    *) eO?OA?IAIEA: AOIE ? AEOAEOE?A access_log AUI N?II OEAUAI ?IOIAO 
       combined, OI ? IIC UA?EOU?AIEOO ?OOOUA OOOIEE; IUEAEA ?IN?EIAOO ? 
       0.3.8.

    *) eO?OA?IAIEA: nginx IA OAAIOAI IA ?IAO?IOIA sparc ?IA IAAUIE OS, 
       EOIIA Solaris.

    *) eO?OA?IAIEA: ? AEOAEOE?A if OA?AOO IA IOOII OAUAAINOO ?OIAAIII 
       OOOIEO ? EA?U?EAE E UAEOU?AAYOA OEIAEO.


eUIAIAIEN ? nginx 0.3.11                                          15.11.2005

    *) eO?OA?IAIEA: nginx IA ?AOAAA?AI ?OE ?OIEOEOI?AIEE OAII UA?OIOA E 
       OOOIEE UACIII?EA EIEAIOA; IUEAEA ?IN?EIAOO ? 0.3.10.


eUIAIAIEN ? nginx 0.3.10                                          15.11.2005

    *) eUIAIAIEA: AEOAEOE?A valid_referers E ?AOAIAIIAN $invalid_referer 
       ?AOAIAOAIU EU IIAOIN ngx_http_rewrite_module ? II?UE IIAOIO 
       ngx_http_referer_module.

    *) eUIAIAIEA: EIN ?AOAIAIIIE "$apache_bytes_sent" EUIAIAII IA 
       "$body_bytes_sent".

    *) aIAA?IAIEA: ?AOAIAIIUA "$sent_http_...".

    *) aIAA?IAIEA: AEOAEOE?A if ?IAAAOOE?AAO I?AOAAEE "=" E "!=".

    *) aIAA?IAIEA: AEOAEOE?A proxy_pass ?IAAAOOE?AAO ?OIOIEII HTTPS.

    *) aIAA?IAIEA: AEOAEOE?A proxy_set_body.

    *) aIAA?IAIEA: AEOAEOE?A post_action.

    *) aIAA?IAIEA: IIAOIO ngx_http_empty_gif_module.

    *) aIAA?IAIEA: AEOAEOE?A worker_cpu_affinity AIN Linux.

    *) eO?OA?IAIEA: AEOAEOE?A rewrite IA OAOEIAEOI?AIA OEI?IIU ? OAAEOAEOAE 
       ? URI, OA?AOO OEI?IIU OAOEIAEOOAOON, EOIIA OEI?III? %00-%25 E 
       %7F-%FF.

    *) eO?OA?IAIEA: nginx IA OIAEOAION EII?EINOIOII icc 9.0.

    *) eO?OA?IAIEA: AOIE AIN OOAOE?AOEICI ?AEIA IOIA?ICI OAUIAOA AUI 
       OAUOAU?I SSI, OI IO?AO ?AOAAA?AION IA?AOII ?OE EIAEOI?AIEE chunk'AIE.


eUIAIAIEN ? nginx 0.3.9                                           10.11.2005

    *) eO?OA?IAIEA: nginx O?EOAI IAAAUI?AOIUIE URI, ? EIOIOUE IAOAO A?OIN 
       OIUUAIE IAEIAEIIOO A?A IAAUE OEI?IIA; IUEAEA ?IN?EIAOO ? 0.3.8.


eUIAIAIEN ? nginx 0.3.8                                           09.11.2005

    *) aAUI?AOIIOOO: nginx OA?AOO ?OI?AONO URI, ?IIO?AIIUA IO AUEAIAA ? 
       OOOIEA "X-Accel-Redirect" ? UACIII?EA IO?AOA, EIE ? SSI ?AEIA IA 
       IAIE?EA ?OOAE "/../" E IOIAE.

    *) eUIAIAIEA: nginx OA?AOO IA ?IO?OEIEIAAO ?OOOIA EIN EAE ?OA?EIOIIA ? 
       OOOIEA "Authorization" ? UACIII?EA UA?OIOA.

    *) aIAA?IAIEA: AEOAEOE?A ssl_session_timeout IIAOIAE 
       ngx_http_ssl_module E ngx_imap_ssl_module.

    *) aIAA?IAIEA: AEOAEOE?A auth_http_header IIAOIN 
       ngx_imap_auth_http_module.

    *) aIAA?IAIEA: AEOAEOE?A add_header.

    *) aIAA?IAIEA: IIAOIO ngx_http_realip_module.

    *) aIAA?IAIEA: II?UA ?AOAIAIIUA AIN EO?IIOUI?AIEN ? AEOAEOE?A 
       log_format: $bytes_sent, $apache_bytes_sent, $status, $time_gmt, 
       $uri, $request_time, $request_length, $upstream_status, 
       $upstream_response_time, $gzip_ratio, $uid_got, $uid_set, 
       $connection, $pipe E $msec. ?AOAIAOOU ? ?EAA "%name" OEIOI AOAOO 
       O?OAUAIAIU.

    *) eUIAIAIEA: ? AEOAEOE?A "if" IIOIUIE UIA?AIENIE ?AOAIAIIUE OA?AOO 
       N?INAOON ?OOOAN OOOIEA "" E OOOIEE, IA?EIAAYEAON IA "0".

    *) eO?OA?IAIEA: ?OE OAAIOAAO O ?OIEOEOI?AIIUIE EIE FastCGI-OAO?AOAIE 
       nginx IIC IOOA?INOO IOEOUOUIE OIAAEIAIEN E ?OAIAIIUA ?AEIU O 
       UA?OIOAIE EIEAIOI?.

    *) eO?OA?IAIEA: OAAI?EA ?OIAAOOU IA OAOAOU?AIE AO?AOEUEOI?AIIUA IICE 
       ?OE ?IA?III ?UEIAA.

    *) eO?OA?IAIEA: AOIE URI UA?OIOA EUIAINIIOO O ?IIIYOA rewrite, A UAOAI 
       UA?OIO ?OIEOEOI?AION ? location, UAAAIIII OACOINOIUI ?UOAOAIEAI, OI 
       AUEAIAO ?AOAAA?AION IA?AOIUE UA?OIO; IUEAEA ?IN?EIAOO ? 0.2.6.

    *) eO?OA?IAIEA: AEOAEOE?A expires IA OAAINIA OOA OOOAII?IAIIOA OOOIEO 
       UACIII?EA "Expires".

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE IAOIAA rtsig E IAOEIIOEEE OAAI?EE 
       ?OIAAOOAE nginx IIC ?AOAOOAOO ?OEIEIAOO UA?OIOU.

    *) eO?OA?IAIEA: ? SSI EIIAIAAE IA?AOII IAOAAAOU?AIEOO OOOIEE "\"" E 
       "\'".

    *) eO?OA?IAIEA: AOIE IO?AO UAEAI?E?AION OOAUO OA ?IOIA SSI EIIAIAU, OI 
       ?OE EO?IIOUI?AIEE OOAOEN IO?AO ?AOAAA?AION IA AI EIIAA EIE IA 
       ?AOAAA?AION ?IIAYA.


eUIAIAIEN ? nginx 0.3.7                                           27.10.2005

    *) aIAA?IAIEA: AEOAEOE?A access_log ?IAAAOOE?AAO ?AOAIAOO buffer=.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA ?IAO?IOIAE, IOIE?IUE IO i386, 
       amd64, sparc E ppc; IUEAEA ?IN?EIAOO ? 0.3.2.


eUIAIAIEN ? nginx 0.3.6                                           24.10.2005

    *) eUIAIAIEA: IMAP/POP3 ?OIEOE OA?AOO IA ?AOAAA?O OAO?AOO A?OIOEUAAEE 
       ?OOOIE IICEI.

    *) aIAA?IAIEA: AEOAEOE?A log_format ?IAAAOOE?AAO ?AOAIAIIUA ? ?EAA 
       $name.

    *) eO?OA?IAIEA: AOIE EION AU ? IAIII OAO?AOA IA AUII I?EOAII IE IAIIE 
       AEOAEOE?U listen, OI nginx IA OIOUAI IA 80 ?IOOO; IUEAEA ?IN?EIAOO ? 
       0.3.3.

    *) eO?OA?IAIEA: AOIE ? AEOAEOE?A proxy_pass IOOOOOO?I?AI URI, OI ?OACAA 
       EO?IIOUI?AION ?IOO 80.


eUIAIAIEN ? nginx 0.3.5                                           21.10.2005

    *) eO?OA?IAIEA: AOIE IICEI IMAP/POP3 IAINION OAO?AOII A?OIOEUAAEE, OI 
       IIC ?OIEUIEOE segmentation fault; IUEAEA ?IN?EIAOO ? 0.2.2.

    *) eO?OA?IAIEA: accept mutex IA OAAIOAI, ?OA OIAAEIAIEN IAOAAAOU?AIEOO 
       IAIEI OAAI?EI ?OIAAOOII; IUEAEA ?IN?EIAOO ? 0.3.3.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE IAOIAA rtsig E AEOAEOE?U 
       timer_resolution IA OAAIOAIE OAEIAOOU.


eUIAIAIEN ? nginx 0.3.4                                           19.10.2005

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA Linux 2.4+ E MacOS X; IUEAEA 
       ?IN?EIAOO ? 0.3.3.


eUIAIAIEN ? nginx 0.3.3                                           19.10.2005

    *) eUIAIAIEA: ?AOAIAOOU "bl" E "af" AEOAEOE?U listen ?AOAEIAII?AIU ? 
       "backlog" E "accept_filter".

    *) aIAA?IAIEA: ?AOAIAOOU "rcvbuf" E "sndbuf" ? AEOAEOE?A listen.

    *) eUIAIAIEA: ?AOAIAOO IICA $msec OA?AOO IA OOAAOAO AI?IIIEOAIOIICI 
       OEOOAIIICI ?UUI?A gettimeofday().

    *) aIAA?IAIEA: EIA? -t OA?AOO ?OI?AONAO AEOAEOE?U listen.

    *) eO?OA?IAIEA: AOIE ? AEOAEOE?A listen AUI OEAUAI IA?AOIUE AAOAO, OI 
       nginx ?IOIA OECIAIA -HUP IOOA?INI IOEOUOUE OIEAO ? OIOOINIEE CLOSED.

    *) eO?OA?IAIEA: AIN EIAAEOIUE ?AEII?, OIAAOOAYEE ? EIAIE ?AOAIAIIOA, 
       IIC IA?AOII ?UOOA?INOOON OE? mime ?I OIII?AIEA; IUEAEA ?IN?EIAOO ? 
       0.3.0.

    *) aIAA?IAIEA: AEOAEOE?A timer_resolution.

    *) aIAA?IAIEA: ?AOAIAOO IICA $upstream_response_time ? IEIIEOAEOIAAE.

    *) eO?OA?IAIEA: ?OAIAIIUE ?AEI O OAIII UA?OIOA EIEAIOA OA?AOO OAAINAOON 
       OOAUO ?IOIA OICI, EAE EIEAIOO ?AOAAAI UACIII?IE IO?AOA.

    *) eO?OA?IAIEA: OI?IAOOEIIOOO O OpenSSL 0.9.6.

    *) eO?OA?IAIEA: ?OOE E ?AEIAI O SSL OAOOE?EEAOII E EIA?II IA IICIE AUOO 
       IOIIOEOAIOIUIE.

    *) eO?OA?IAIEA: AEOAEOE?A ssl_prefer_server_ciphers IA OAAIOAIA AIN 
       IIAOIN ngx_imap_ssl_module.

    *) eO?OA?IAIEA: AEOAEOE?A ssl_protocols ?IU?IINIA UAAAOO OIIOEI IAEI 
       ?OIOIEII.


eUIAIAIEN ? nginx 0.3.2                                           12.10.2005

    *) aIAA?IAIEA: ?IAAAOOEA Sun Studio 10 C compiler.

    *) aIAA?IAIEA: AEOAEOE?U proxy_upstream_max_fails, 
       proxy_upstream_fail_timeout, fastcgi_upstream_max_fails E 
       fastcgi_upstream_fail_timeout.


eUIAIAIEN ? nginx 0.3.1                                           10.10.2005

    *) eO?OA?IAIEA: ?I ?OAIN ?AOA?IIIAIEN I?AOAAE OECIAII? ?OE 
       EO?IIOUI?AIEE IAOIAA rtsig ?OIEOEIAEI segmentation fault; IUEAEA 
       ?IN?EIAOO ? 0.2.0.

    *) eUIAIAIEA: EIOOAEOIAN IAOAAIOEA ?AO "\\", "\"", "\'" E "\$" ? SSI.


eUIAIAIEN ? nginx 0.3.0                                           07.10.2005

    *) eUIAIAIEA: OAOAII AAONOEAIA?IIA ICOAIE?AIEA ?OAIAIE OAAIOU OAAI?ACI 
       ?OIAAOOA. iCOAIE?AIEA AUII ??AAAII EU-UA ?AOA?IIIAIEN IEIIEOAEOIAIUE 
       OAEIAOI?.


eUIAIAIEN ? nginx 0.2.6                                           05.10.2005

    *) eUIAIAIEA: O 60 AI 10 OAEOIA OIAIOUAII ?OAIN ?I?OIOIICI IAOAYAIEN E 
       AUEAIAO ?OE EO?IIOUI?AIEE OAO?OAAAIAIEN IACOOUEE.

    *) eUIAIAIEA: AEOAEOE?A proxy_pass_unparsed_uri O?OAUAIAIA, 
       IOECEIAIOIUE UA?OIO OA?AOO ?AOAAA?OON, AOIE ? AEOAEOE?A proxy_pass 
       IOOOOOO?OAO URI.

    *) aIAA?IAIEA: AEOAEOE?A error_page ?IAAAOOE?AAO OAAEOAEOU E ?IU?IINAO 
       AIIAA CEAEI IAINOO EIA IUEAEE.

    *) eUIAIAIEA: ? ?OIEOEOI?AIIUE ?IAUA?OIOAE OA?AOO ECIIOEOOAOON 
       ?AOAAAIIUE charset.

    *) eO?OA?IAIEA: AOIE ?IOIA EUIAIAIEN URI ? AIIEA if AIN UA?OIOA IA 
       IAEIAEIAOO II?AN EII?ECOOAAEN, OI ?OA?EIA IIAOIN 
       ngx_http_rewrite_module ?U?IIINIEOO OII?A.

    *) eO?OA?IAIEA: AOIE AEOAEOE?A set OOOAIA?IE?AIA ?AOAIAIIOA IIAOIN 
       ngx_http_geo_module ? EAEIE-IEAI ?AOOE EII?ECOOAAEE, OI UOA 
       ?AOAIAIIAN IA AUIA AIOOO?IA ? AOOCEE ?AOONE EII?ECOOAAEE E 
       ?UAA?AIAOO IUEAEA "using uninitialized variable"; IUEAEA ?IN?EIAOO ? 
       0.2.2.


eUIAIAIEN ? nginx 0.2.5                                           04.10.2005

    *) eUIAIAIEA: AOAIEOOAYAA UIA?AIEA ?AOAIAIIIE IIAOIN 
       ngx_http_geo_module OA?AOO ?UAA?O ?OAAO?OAOAAIEA E EUIAINAO OOAOIA 
       UIA?AIEA.

    *) aIAA?IAIEA: IIAOIO ngx_http_ssi_module ?IAAAOOE?AAO EIIAIAO set.

    *) aIAA?IAIEA: IIAOIO ngx_http_ssi_module ?IAAAOOE?AAO ?AOAIAOO file ? 
       EIIAIAA include.

    *) aIAA?IAIEA: IIAOIO ngx_http_ssi_module ?IAAAOOE?AAO ?IAOOAII?EO 
       UIA?AIEE ?AOAIAIIUE ? ?UOAOAIENE EIIAIAU if.


eUIAIAIEN ? nginx 0.2.4                                           03.10.2005

    *) aIAA?IAIEA: IIAOIO ngx_http_ssi_module ?IAAAOOE?AAO ?UOAOAIEN 
       "$var=text", "$var!=text", "$var=/text/" E "$var!=/text/" ? EIIAIAA 
       if.

    *) eO?OA?IAIEA: IUEAEE ?OE ?OIEOEOI?AIEE location AAU OIUUA ? EIIAA; 
       IUEAEA ?IN?EIAOO ? 0.1.44.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE IAOIAA rtsig IIC ?OIEUIEOE 
       segmentation fault; IUEAEA ?IN?EIAOO ? 0.2.0.


eUIAIAIEN ? nginx 0.2.3                                           30.09.2005

    *) eO?OA?IAIEA: nginx IA OIAEOAION AAU ?AOAIAOOA --with-debug; IUEAEA 
       ?IN?EIAOO ? 0.2.2.


eUIAIAIEN ? nginx 0.2.2                                           30.09.2005

    *) aIAA?IAIEA: EIIAIAA config errmsg ? IIAOIA ngx_http_ssi_module.

    *) eUIAIAIEA: ?AOAIAIIUA IIAOIN ngx_http_geo_module IIOII 
       ?AOAI?OAAAINOO AEOAEOE?IE set.

    *) aIAA?IAIEA: AEOAEOE?U ssl_protocols E ssl_prefer_server_ciphers 
       IIAOIAE ngx_http_ssl_module E ngx_imap_ssl_module.

    *) eO?OA?IAIEA: IUEAEA ? IIAOIA ngx_http_autoindex_module ?OE ?IEAUA 
       AIEIIUE EI?I ?AEII?;

    *) eO?OA?IAIEA: IIAOIO ngx_http_autoindex_module OA?AOO IA ?IEAUU?AAO 
       ?AEIU, IA?EIAAYEAON IA OI?EO.

    *) eO?OA?IAIEA: AOIE SSL handshake UA?AOUAION O IUEAEIE, OI UOI IICII 
       ?OE?AOOE OAEOA E UAEOUOEA AOOCICI OIAAEIAIEN.
       o?AOEAI Rob Mueller.

    *) eO?OA?IAIEA: UEO?IOOIUA ?AOOEE MSIE 5.x IA IICIE OIAAEIEOOON ?I 
       HTTPS.


eUIAIAIEN ? nginx 0.2.1                                           23.09.2005

    *) eO?OA?IAIEA: AOIE ?OA AUEAIAU, EO?IIOUOAIUA AIN AAIAIOEOI?EE 
       IACOOUEE, IEAUU?AIEOO ? IAOAAI?AI OIOOINIEE ?IOIA IAIIE IUEAEE, OI 
       nginx IIC UAAEEIEOON; IUEAEA ?IN?EIAOO ? 0.2.0.


eUIAIAIEN ? nginx 0.2.0                                           23.09.2005

    *) eUIAIEIEOO EIAIA pid-?AEII?, EO?IIOUOAIUA ?I ?OAIN IAII?IAIEN 
       EO?IIINAIICI ?AEIA. oO?IIA ?AOAEIAII?AIEA OA?AOO IA IOOII. oOAOUE 
       IOII?IIE ?OIAAOO AIAA?INAO E O?IAIO pid-?AEI OO??EEO ".oldbin" E 
       UA?OOEAAO II?UE EO?IIINAIUE ?AEI. iI?UE IOII?IIE ?OIAAOO OIUAA?O 
       IAU?IUE pid-?AEI AAU OO??EEOA ".newbin". aOIE II?UE IOII?IIE ?OIAAOO 
       ?UEIAEO, OI OOAOUE ?OIAAOO ?AOAEIAII?U?AAO O?IE pid-?AEI c OO??EEOII 
       ".oldbin" ? pid-?AEI AAU OO??EEOA. ?OE IAII?IAIEE O ?AOOEE 0.1.E AI 
       0.2.0 IOOII O?EOU?AOO, ?OI IAA ?OIAAOOA - OOAOUE 0.1.x E II?UE 
       0.2.0 - EO?IIOUOAO pid-?AEI AAU OO??EEOI?.

    *) eUIAIAIEA: AEOAEOE?A worker_connections, II?IA IAU?AIEA AEOAEOE?U 
       connections; AEOAEOE?A OA?AOO UAAA?O IAEOEIAIOIIA ?EOII OIAAEIAIEE, 
       A IA IAEOEIAIOII ?IUIIOIUE IIIAO AAOEOE?OIOA AIN OIEAOA.

    *) aIAA?IAIEA: SSL ?IAAAOOE?AAO EUUEOI?AIEA OAOOEE ? ?OAAAIAE IAIICI 
       OAAI?ACI ?OIAAOOA.

    *) aIAA?IAIEA: AEOAEOE?A satisfy_any.

    *) eUIAIAIEA: IIAOIE ngx_http_access_module E 
       ngx_http_auth_basic_module IA OAAIOAAO AIN ?IAUA?OIOI?.

    *) aIAA?IAIEA: AEOAEOE?U worker_rlimit_nofile E 
       worker_rlimit_sigpending.

    *) eO?OA?IAIEA: AOIE ?OA AUEAIAU, EO?IIOUOAIUA AIN AAIAIOEOI?EE 
       IACOOUEE, IEAUU?AIEOO ? IAOAAI?AI OIOOINIEE ?IOIA IAIIE IUEAEE, OI 
       nginx IA IAOAYAION E IEI ? OA?AIEA 60 OAEOIA.

    *) eO?OA?IAIEA: ? ?AOOEICA AOCOIAIOI? IMAP/POP3 EIIAIA.
       o?AOEAI Rob Mueller.

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE SSL ? IMAP/POP3 ?OIEOE.

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE SSI E OOAOEN.

    *) eO?OA?IAIEA: ? IO?AOAE 304 IA AIAA?INIEOO OOOIEE UACIII?EA IO?AOA 
       "Expires" E "Cache-Control".
       o?AOEAI aIAEOAIAOO eOEOUEEIO.


eUIAIAIEN ? nginx 0.1.45                                          08.09.2005

    *) eUIAIAIEA: AEOAEOE?A ssl_engine O?OAUAIAIA ? IIAOIA 
       ngx_http_ssl_module E ?AOAIAOAIA IA CIIAAIOIUE OOI?AIO.

    *) eO?OA?IAIEA: IO?AOU O ?IAUA?OIOAIE, ?EIA??IIUA O ?IIIYOA SSI, IA 
       ?AOAAA?AIEOO ?AOAU SSL OIAAEIAIEA.

    *) oAUIUA EO?OA?IAIEN ? IMAP/POP3 ?OIEOE.


eUIAIAIEN ? nginx 0.1.44                                          06.09.2005

    *) aIAA?IAIEA: IMAP/POP3 ?OIEOE ?IAAAOOE?AAO SSL.

    *) aIAA?IAIEA: AEOAEOE?A proxy_timeout IIAOIN ngx_imap_proxy_module.

    *) aIAA?IAIEA: AEOAEOE?A userid_mark.

    *) aIAA?IAIEA: UIA?AIEA ?AOAIAIIIE $remote_user I?OAAAINAOON IAUA?EOEII 
       IO OICI, EO?IIOUOAOON IE A?OIOEUAAEN EIE IAO.


eUIAIAIEN ? nginx 0.1.43                                          30.08.2005

    *) aIAA?IAIEA: listen(2) backlog ? AEOAEOE?A listen IIOII IAINOO ?I 
       OECIAIO -HUP.

    *) aIAA?IAIEA: OEOE?O geo2nginx.pl AIAA?IAI ? contrib.

    *) eUIAIAIEA: ?AOAIAOOU FastCGI O ?OOOUI UIA?AIENIE OA?AOO ?AOAAAAOON 
       OAO?AOO.

    *) eO?OA?IAIEA: AOIE ? IO?AOA ?OIEOEOI?AIIICI OAO?AOA EIE FastCGI 
       OAO?AOA AUIA OOOIEA "Cache-Control", OI ?OE EO?IIOUI?AIEE AEOAEOE?U 
       expires ?OIEOEIAEI segmentation fault EIE OAAI?EE ?OIAAOO IIC 
       UAAEEIEOON; ? OAOEIA ?OIEOE IUEAEA ?IN?EIAOO ? 0.1.29.


eUIAIAIEN ? nginx 0.1.42                                          23.08.2005

    *) eO?OA?IAIEA: AOIE URI UA?OIOA ?IIO?AION IOIA?IE AIEIU ?IOIA 
       IAOAAIOEE IIAOIAI ngx_http_rewrite_module, OI ? IIAOIA 
       ngx_http_proxy_module ?OIEOEIAEI segmentation fault EIE bus error.

    *) eO?OA?IAIEA: AEOAEOE?A limit_rate IA OAAIOAIA ?IOOOE AIIEA if; 
       IUEAEA ?IN?EIAOO ? 0.1.38.


eUIAIAIEN ? nginx 0.1.41                                          25.07.2005

    *) eO?OA?IAIEA: AOIE ?AOAIAIIAN EO?IIOUI?AIAOO ? ?AEIA EII?ECOOAAEE, OI 
       IIA IA IICIA EO?IIOUI?AOOON ? SSI.


eUIAIAIEN ? nginx 0.1.40                                          22.07.2005

    *) eO?OA?IAIEA: AOIE EIEAIO OIAI I?AIO AIEIIOA OOOIEO UACIII?EA, OI ? 
       IICA IA ?IIAYAIAOO EI?IOIAAEN, O?NUAIIAN O UOEI UA?OIOII.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE "X-Accel-Redirect" IA ?AOAAA?AIAOO 
       OOOIEA "Set-Cookie"; IUEAEA ?IN?EIAOO ? 0.1.39.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE "X-Accel-Redirect" IA ?AOAAA?AIAOO 
       OOOIEA "Content-Disposition".

    *) eO?OA?IAIEA: ?I OECIAIO SIGQUIT IOII?IIE ?OIAAOO IA UAEOU?AI OIEAOU, 
       IA EIOIOUE II OIOUAI.

    *) eO?OA?IAIEA: ?IOIA IAII?IAIEN EO?IIINAIICI ?AEIA IA IAOO IA Linux E 
       Solaris IAU?AIEA ?OIAAOOA ? EIIAIAA ps OOAII?EIIOO EIOI?A.


eUIAIAIEN ? nginx 0.1.39                                          14.07.2005

    *) eUIAIAIEN ? IIAOIA ngx_http_charset_module: AEOAEOE?A 
       default_charset O?OAUAIAIA; AEOAEOE?A charset UAAA?O EIAEOI?EO 
       IO?AOA; AEOAEOE?A source_charset UAAA?O OIIOEI EOEIAIOA EIAEOI?EO.

    *) eO?OA?IAIEA: ?OE ?AOAIA?OA?IAIEE IUEAEE 401, ?IIO?AIIIE IO AUEAIAA, 
       IA ?AOAAA?AIAOO OOOIEA UACIII?EA "WWW-Authenticate".

    *) eO?OA?IAIEA: IIAOIE ngx_http_proxy_module E ngx_http_fastcgi_module 
       IICIE UAEOUOO OIAAEIAIEA AI OICI, EAE ?OI-IEAOAO AUII ?AOAAAII 
       EIEAIOO; IUEAEA ?IN?EIAOO ? 0.1.38.

    *) eUIAIAIEA: IAOAAIOEA IUEAEE EIEAEAIEUAAEE ? crypt_r() ? Linux glibc.

    *) eO?OA?IAIEA: IIAOIO ngx_http_ssi_module IA ?IAAAOOE?AI IOIIOEOAIOIUA 
       URI ? EIIAIAA include virtual.

    *) eO?OA?IAIEA: AOIE ? OOOIEA UACIII?EA IO?AOA AUEAIAA AUIA OOOIEA 
       "Location", EIOIOOA nginx IA AIIOAI AUI EUIAINOO, OI ? IO?AOA 
       ?AOAAA?AIIOO OAII 500 IUEAEE; IUEAEA ?IN?EIAOO ? 0.1.29.

    *) eO?OA?IAIEA: IAEIOIOUA AEOAEOE?U IIAOIAE ngx_http_proxy_module E 
       ngx_http_fastcgi_module IA IAOIAAI?AIEOO O OOI?IN server IA OOI?AIO 
       location; IUEAEA ?IN?EIAOO ? 0.1.29.

    *) eO?OA?IAIEA: IIAOIO ngx_http_ssl_module IA ?IAAAOOE?AI AA?I?EE 
       OAOOE?EEAOI?.

    *) eO?OA?IAIEA: IUEAEA ? IIAOIA ngx_http_autoindex_module ?OE ?IEAUA 
       AIEIIUE EI?I ?AEII?; IUEAEA ?IN?EIAOO ? 0.1.38.

    *) eO?OA?IAIEN ? IMAP/POP3 ?OIEOE ?OE ?UAEIIAAEOO?EE O AUEAIAII IA 
       OOAAEE login.


eUIAIAIEN ? nginx 0.1.38                                          08.07.2005

    *) aIAA?IAIEA: AEOAEOE?A limit_rate ?IAAAOOE?AAOON ? OAOEIA ?OIEOE E 
       FastCGI.

    *) aIAA?IAIEA: ? OAOEIA ?OIEOE E FastCGI ?IAAAOOE?AAOON OOOIEA 
       UACIII?EA "X-Accel-Limit-Rate" ? IO?AOA AUEAIAA.

    *) aIAA?IAIEA: AEOAEOE?A break.

    *) aIAA?IAIEA: AEOAEOE?A log_not_found.

    *) eO?OA?IAIEA: ?OE ?AOAIA?OA?IAIEE UA?OIOA O ?IIIYOA OOOIEE UACIII?EA 
       "X-Accel-Redirect" IA EUIAINION EIA IO?AOA.

    *) eO?OA?IAIEA: ?AOAIAIIUA, OOOAII?IAIIUA AEOAEOE?IE set IA IICIE 
       EO?IIOUI?AOOON ? SSI.

    *) eO?OA?IAIEA: ?OE ?EIA?AIEE ? SSI AIIAA IAIICI OAAI?IIICI ?IAUA?OIOA 
       IIC ?OIEUIEOE segmentation fault.

    *) eO?OA?IAIEA: AOIE OOAOOOIAN OOOIEA ? IO?AOA AUEAIAA ?AOAAA?AIAOO ? 
       A?OE ?AEAOAE, OI nginx O?EOAI IO?AO IA?AOIUI; IUEAEA ?IN?EIAOO ? 
       0.1.29.

    *) aIAA?IAIEA: AEOAEOE?A ssi_types.

    *) aIAA?IAIEA: AEOAEOE?A autoindex_exact_size.

    *) eO?OA?IAIEA: IIAOIO ngx_http_autoindex_module IA ?IAAAOOE?AI AIEIIUA 
       EIAIA ?AEII? ? UTF-8.

    *) aIAA?IAIEA: IMAP/POP3 ?OIEOE.


eUIAIAIEN ? nginx 0.1.37                                          23.06.2005

    *) eUIAIAIEA: ? EIIAA ?AEIA nginx.pid OA?AOO AIAA?INAOON "\n".

    *) eO?OA?IAIEA: ?OE ?EIA?AIEE AIIOUICI EIIE?AOO?A ?OOA?IE EIE 
       IAOEIIOEEE AIIOUEE ?OOA?IE O ?IIIYOA SSI IO?AO IIC ?AOAAA?AOOON IA 
       ?IIIIOOOA.

    *) eO?OA?IAIEA: AOIE ?OA AUEAIAU ?IU?OAYAIE IO?AO 404, OI ?OE 
       EO?IIOUI?AIEE ?AOAIAOOA http_404 ? AEOAEOE?AE proxy_next_upstream 
       EIE fastcgi_next_upstream, nginx IA?EIAI UA?OAUE?AOO ?OA AUEAIAU 
       OII?A.


eUIAIAIEN ? nginx 0.1.36                                          15.06.2005

    *) eUIAIAIEA: AOIE ? UACIII?EA UA?OIOA AOOO AOAIEOOAYEAON OOOIEE 
       "Host", "Connection", "Content-Length" E "Authorization", OI nginx 
       OA?AOO ?UAA?O IUEAEO 400.

    *) eUIAIAIEA: AEOAEOE?A post_accept_timeout O?OAUAIAIA.

    *) aIAA?IAIEA: ?AOAIAOOU default, af=, bl=, deferred E bind ? AEOAEOE?A 
       listen.

    *) aIAA?IAIEA: ?IAAAOOEA accept ?EIOOOI? ?I FreeBSD.

    *) aIAA?IAIEA: ?IAAAOOEA TCP_DEFER_ACCEPT ? Linux.

    *) eO?OA?IAIEA: IIAOIO ngx_http_autoindex_module IA ?IAAAOOE?AI EIAIA 
       ?AEII? ? UTF-8.

    *) eO?OA?IAIEA: ?IOIA AIAA?IAIEN II?UE IIC-?AEI OIOAAEN UOICI IICA ?I 
       OECIAIO -USR1 ?U?IIINIAOO, OIIOEI AOIE ?AOAEII?ECOOEOI?AOO nginx A?A 
       OAUA ?I OECIAIO -HUP.


eUIAIAIEN ? nginx 0.1.35                                          07.06.2005

    *) aIAA?IAIEA: AEOAEOE?A working_directory.

    *) aIAA?IAIEA: AEOAEOE?A port_in_redirect.

    *) eO?OA?IAIEA: AOIE UACIII?IE IO?AOA AUEAIAA IA ?IIAYAION ? IAEI 
       ?AEAO, OI ?OIEOEIAEI segmentation fault; IUEAEA ?IN?EIAOO ? 0.1.29.

    *) eO?OA?IAIEA: AOIE AUII OEII?ECOOEOI?AII AIIAA 10 OAO?AOI? EIE ? 
       OAO?AOA IA I?EOAIA AEOAEOE?A "listen", OI ?OE UA?OOEA IIC ?OIEUIEOE 
       segmentation fault.

    *) eO?OA?IAIEA: AOIE IO?AO IA ?IIAYAION ?I ?OAIAIIUE ?AEI, OI IIC 
       ?OIEUIEOE segmentation fault.

    *) eO?OA?IAIEA: nginx ?IU?OAYAI IUEAEO 400 IA UA?OIOU ?EAA 
       "GET http://www.domain.com/uri HTTP/1.0"; IUEAEA ?IN?EIAOO ? 0.1.28.


eUIAIAIEN ? nginx 0.1.34                                          26.05.2005

    *) eO?OA?IAIEA: ?OE ?EIA?AIEE AIIOUEE IO?AOI? O ?IIIYOA SSI OAAI?EE 
       ?OIAAOO IIC UAAEEIEOOON.

    *) eO?OA?IAIEA: ?AOAIAIIUA, OOOAIA?IE?AAIUA AEOAEOE?IE "set", IA AUIE 
       AIOOO?IU ? SSI.

    *) aIAA?IAIEA: AEOAEOE?A autoindex_localtime.

    *) eO?OA?IAIEA: ?OOOIA UIA?AIEA ? AEOAEOE?A proxy_set_header UA?OAYAAO 
       ?AOAAA?O UACIII?EA.


eUIAIAIEN ? nginx 0.1.33                                          23.05.2005

    *) eO?OA?IAIEA: nginx IA OIAEOAION O ?AOAIAOOII --without-pcre; IUEAEA 
       ?IN?EIAOO ? 0.1.29.

    *) eO?OA?IAIEA: 3, 5, 7 E 8 AEOAEOE? proxy_set_header IA IAIII OOI?IA 
       ?UUU?AIE bus fault ?OE UA?OOEA.

    *) eO?OA?IAIEA: ? OAAEOAEOAE ?IOOOE HTTPS OAO?AOA AUI OEAUAI ?OIOIEII 
       HTTP.

    *) eO?OA?IAIEA: AOIE AEOAEOE?A rewrite EO?IIOUI?AIA ?UAAIAIEN ?IOOOE 
       AEOAEOE?U if, OI ?IU?OAYAIAOO IUEAEA 500.


eUIAIAIEN ? nginx 0.1.32                                          19.05.2005

    *) eO?OA?IAIEA: ? OAAEOAEOAE, ?UAA?AAIUE O ?IIIYOA AEOAEOE?U rewrite, 
       IA ?AOAAA?AIEOO AOCOIAIOU; IUEAEA ?IN?EIAOO ? 0.1.29.

    *) aIAA?IAIEA: AEOAEOE?A if ?IAAAOOE?AAO ?UAAIAIEN ? OACOINOIUE 
       ?UOAOAIENE.

    *) aIAA?IAIEA: AEOAEOE?A set ?IAAAOOE?AAO ?AOAIAIIUA E ?UAAIAIEN EU 
       OACOINOIUE ?UOAOAIEE.

    *) aIAA?IAIEA: ? OAOEIA ?OIEOE E FastCGI ?IAAAOOE?AAOON OOOIEA 
       UACIII?EA "X-Accel-Redirect" ? IO?AOA AUEAIAA.


eUIAIAIEN ? nginx 0.1.31                                          16.05.2005

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE SSL IO?AO IIC ?AOAAA?AOOON IA AI 
       EIIAA.

    *) eO?OA?IAIEA: IUEAEE ?OE IAOAAIOEA SSI ? IO?AOA, ?IIO?AIIICI IO 
       FastCGI-OAO?AOA.

    *) eO?OA?IAIEA: IUEAEE ?OE EO?IIOUI?AIEE SSI E OOAOEN.

    *) eO?OA?IAIEA: OAAEOAEO O EIAII 301 ?AOAAA?AION AAU OAIA IO?AOA; 
       IUEAEA ?IN?EIAOO ? 0.1.30.


eUIAIAIEN ? nginx 0.1.30                                          14.05.2005

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE SSI OAAI?EE ?OIAAOO IIC UAAEEIEOOON.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE SSL IO?AO IIC ?AOAAA?AOOON IA AI 
       EIIAA.

    *) eO?OA?IAIEA: AOIE AIEIA ?AOOE IO?AOA, ?IIO?AIIICI UA IAEI OAU IO 
       ?OIEOEOOAIICI EIE FastCGI OAO?AOA AUIA OA?IA 500 AAEO, OI nginx 
       ?IU?OAYAI EIA IO?AOA 500; ? OAOEIA ?OIEOE IUEAEA ?IN?EIAOO OIIOEI ? 
       0.1.29.

    *) eO?OA?IAIEA: nginx IA O?EOAI IA?AOIUIE AEOAEOE?U O 8-A EIE 9-A 
       ?AOAIAOOAIE.

    *) aIAA?IAIEA: AEOAEOE?A return IIOAO ?IU?OAYAOO EIA IO?AOA 204.

    *) aIAA?IAIEA: AEOAEOE?A ignore_invalid_headers.


eUIAIAIEN ? nginx 0.1.29                                          12.05.2005

    *) aIAA?IAIEA: IIAOIO ngx_http_ssi_module ?IAAAOOE?AAO EIIAIAO include 
       virtual.

    *) aIAA?IAIEA: IIAOIO ngx_http_ssi_module ?IAAAOOE?AAO OOII?IOA EIIAIAO 
       ?EAA 'if expr="$NAME"' E EIIAIAU else E endif. aI?OOEAAOON OIIOEI 
       IAEI OOI?AIO ?IIOAIIIOOE.

    *) aIAA?IAIEA: IIAOIO ngx_http_ssi_module ?IAAAOOE?AAO A?A ?AOAIAIIUA 
       DATE_LOCAL E DATE_GMT E EIIAIAO config timefmt.

    *) aIAA?IAIEA: AEOAEOE?A ssi_ignore_recycled_buffers.

    *) eO?OA?IAIEA: AOIE ?AOAIAIIAN QUERY_STRING IA AUIA I?OAAAIAIA, OI ? 
       EIIAIAA echo IA OOA?EIIOO UIA?AIEA ?I OIII?AIEA.

    *) eUIAIAIEA: IIAOIO ngx_http_proxy_module ?IIIIOOOA ?AOA?EOAI.

    *) aIAA?IAIEA: AEOAEOE?U proxy_redirect, proxy_pass_request_headers, 
       proxy_pass_request_body E proxy_method.

    *) aIAA?IAIEA: AEOAEOE?A proxy_set_header. aEOAEOE?A proxy_x_var 
       O?OAUAIAIA E AIIOIA AUOO UAIAIAIA AEOAEOE?IE proxy_set_header.

    *) eUIAIAIEA: AEOAEOE?A proxy_preserve_host O?OAUAIAIA E AIIOIA AUOO 
       UAIAIAIA AEOAEOE?AIE "proxy_set_header Host $host" E "proxy_redirect 
       off" EIE AEOAEOE?IE "proxy_set_header Host $host:$proxy_port" E 
       OIIO?AOOO?OAYEIE AE AEOAEOE?AIE proxy_redirect.

    *) eUIAIAIEA: AEOAEOE?A proxy_set_x_real_ip O?OAUAIAIA E AIIOIA AUOO 
       UAIAIAIA AEOAEOE?IE "proxy_set_header X-Real-IP $remote_addr".

    *) eUIAIAIEA: AEOAEOE?A proxy_add_x_forwarded_for O?OAUAIAIA E AIIOIA 
       AUOO UAIAIAIA AEOAEOE?IE 
       "proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for".

    *) eUIAIAIEA: AEOAEOE?A proxy_set_x_url O?OAUAIAIA E AIIOIA AUOO 
       UAIAIAIA AEOAEOE?IE 
       "proxy_set_header X-URL http://$host:$server_port$request_uri".

    *) aIAA?IAIEA: AEOAEOE?A fastcgi_param.

    *) eUIAIAIEA: AEOAEOE?U fastcgi_root, fastcgi_set_var E fastcgi_params 
       O?OAUAIAIU E AIIOIU AUOO UAIAIU AEOAEOE?AIE fastcgi_param.

    *) aIAA?IAIEA: AEOAEOE?A index IIOAO EO?IIOUI?AOO ?AOAIAIIUA.

    *) aIAA?IAIEA: AEOAEOE?A index IIOAO AUOO OEAUAIA IA OOI?IA http E 
       server.

    *) eUIAIAIEA: OIIOEI ?IOIAAIEE ?AOAIAOO ? AEOAEOE?A index IIOAO AUOO 
       AAOIIAOIUI.

    *) aIAA?IAIEA: ? AEOAEOE?A rewrite IICOO EO?IIOUI?AOOON ?AOAIAIIUA.

    *) aIAA?IAIEA: AEOAEOE?A internal.

    *) aIAA?IAIEA: ?AOAIAIIUA CONTENT_LENGTH, CONTENT_TYPE, REMOTE_PORT, 
       SERVER_ADDR, SERVER_PORT, SERVER_PROTOCOL, DOCUMENT_ROOT, 
       SERVER_NAME, REQUEST_METHOD, REQUEST_URI E REMOTE_USER.

    *) eUIAIAIEA: nginx OA?AOO ?AOAAA?O IA?AOIUA OOOIEE ? UACIII?EAE 
       UA?OIOA EIEAIOA E IO?AOA AUEAIAA.

    *) eO?OA?IAIEA: AOIE AUEAIA AIICI IA ?AOAAA?AI IO?AO E send_timeout AUI 
       IAIOUA, ?AI proxy_read_timeout, OI EIEAIOO ?IU?OAYAION IO?AO 408.

    *) eO?OA?IAIEA: AOIE AUEAIA ?AOAAA?AI IA?AOIOA OOOIEO ? UACIII?EA 
       IO?AOA, OI ?OIEOEIAEI segmentation fault; IUEAEA ?IN?EIAOO ? 0.1.26.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE IOEAUIOOOIE?E?IE EII?ECOOAAEE ? 
       FastCGI IIC ?OIEOEIAEOO segmentation fault.

    *) eO?OA?IAIEA: AEOAEOE?A expires IA OAAINIA OOA OOOAII?IAIIUA OOOIEE 
       UACIII?EA "Expires" E "Cache-Control".

    *) eO?OA?IAIEA: nginx IA O?EOU?AI UA?AOUAAYOA OI?EO ? OOOIEA UACIII?EA 
       UA?OIOA "Host".

    *) eO?OA?IAIEA: IIAOIO ngx_http_auth_module IA OAAIOAI IA Linux.

    *) eO?OA?IAIEA: AEOAEOE?A rewrite IA?AOII OAAIOAIA, AOIE ? UA?OIOA 
       ?OEOOOOO?I?AIE AOCOIAIOU.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA MacOS X.


eUIAIAIEN ? nginx 0.1.28                                          08.04.2005

    *) eO?OA?IAIEA: ?OE ?OIEOEOI?AIEE AIIOUEE ?AEII? nginx OEIOII IACOOOAI 
       ?OIAAOOIO.

    *) eO?OA?IAIEA: nginx IA OIAEOAION gcc 4.0 IA Linux.


eUIAIAIEN ? nginx 0.1.27                                          28.03.2005

    *) aIAA?IAIEA: ?AOAIAOO blocked ? AEOAEOE?A valid_referers.

    *) eUIAIAIEA: IUEAEE IAOAAIOEE UACIII?EA UA?OIOA OA?AOO UA?EOU?AAOON IA 
       OOI?IA info, ? IIC OAEOA UA?EOU?AAOON EIN OAO?AOA E OOOIEE UACIII?EA 
       UA?OIOA "Host" E "Referer".

    *) eUIAIAIEA: ?OE UA?EOE IUEAIE ? IIC UA?EOU?AAOON OAEOA OOOIEA 
       UACIII?EA UA?OIOA "Host".

    *) aIAA?IAIEA: AEOAEOE?A proxy_pass_unparsed_uri. o?AAEAIOIAN IAOAAIOEA 
       OEI?III? "://" ? URI, ??AA?IIAN ? ?AOOEE 0.1.11, OA?AOO O?OAUAIAIA.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA FreeBSD E Linux, AOIE AUI OEAUAI 
       ?AOAIAOO EII?ECOOAAEE --without-ngx_http_auth_basic_module.


eUIAIAIEN ? nginx 0.1.26                                          22.03.2005

    *) eUIAIAIEA: IA?AOIUA OOOIEE UACIII?EA, ?AOAAAIIUA EIEAIOII, OA?AOO 
       ECIIOEOOAOON E UA?EOU?AAOON ? error_log IA OOI?IA info.

    *) eUIAIAIEA: ?OE UA?EOE IUEAIE ? IIC UA?EOU?AAOON OAEOA EIN OAO?AOA, 
       ?OE IAOAYAIEE E EIOIOIIO ?OIEUIUIA IUEAEA.

    *) aIAA?IAIEA: IIAOIO ngx_http_auth_basic_module E AEOAEOE?U auth_basic 
       E auth_basic_user_file.


eUIAIAIEN ? nginx 0.1.25                                          19.03.2005

    *) eO?OA?IAIEA: nginx IA OAAIOAI IA Linux parisc.

    *) aIAA?IAIEA: nginx OA?AOO IA UA?OOEAAOON ?IA FreeBSD, AOIE UIA?AIEA 
       sysctl kern.ipc.somaxconn OIEUEII AIIOUIA.

    *) eO?OA?IAIEA: AOIE IIAOIO ngx_http_index_module AAIAI ?IOOOAIIAA 
       ?AOAIA?OA?IAIEA UA?OIOA ? IIAOIE ngx_http_proxy_module EIE 
       ngx_http_fastcgi_module, OI ?AEI EIAAEOA IA UAEOU?AION ?IOIA 
       IAOIOOE?AIEN UA?OIOA.

    *) aIAA?IAIEA: AEOAEOE?A proxy_pass IIOAO EO?IIOUI?AOOON ? location, 
       UAAAIIUE OACOINOIUI ?UOAOAIEAI.

    *) aIAA?IAIEA: IIAOIO ngx_http_rewrite_filter_module ?IAAAOOE?AAO 
       OOII?EN ?EAA "if ($HTTP_USER_AGENT ~ MSIE)".

    *) eO?OA?IAIEA: nginx I?AIO IAAIAIII UA?OOEAION ?OE AIIOUII EIIE?AOO?A 
       AAOAOI? E EO?IIOUI?AIEE OAEOOI?UE UIA?AIEE ? AEOAEOE?A geo.

    *) eUIAIAIEA: EIN ?AOAIAIIIE ? AEOAEOE?A geo IOOII OEAUU?AOO, EAE 
       $name. ?OAOIEE ?AOEAIO AAU "$" ?IEA OAAIOAAO, II ?OEIOA AOAAO OAOAI.

    *) aIAA?IAIEA: ?AOAIAOO IICA "%{VARIABLE}v".

    *) aIAA?IAIEA: AEOAEOE?A "set $name value".

    *) eO?OA?IAIEA: OI?IAOOEIIOOO O gcc 4.0.

    *) aIAA?IAIEA: ?AOAIAOO A?OIEII?ECOOAAEE --with-openssl-opt=OPTIONS.


eUIAIAIEN ? nginx 0.1.24                                          04.03.2005

    *) aIAA?IAIEA: IIAOIO ngx_http_ssi_filter_module ?IAAAOOE?AAO 
       ?AOAIAIIUA QUERY_STRING E DOCUMENT_URI.

    *) eO?OA?IAIEA: IIAOIO ngx_http_autoindex_module IIC ?UAA?AOO IO?AO 404 
       IA OOYAOO?OAYEE EAOAIIC, AOIE UOIO EAOAIIC AUI OEAUAI EAE alias.

    *) eO?OA?IAIEA: IIAOIO ngx_http_ssi_filter_module IA?OA?EIOII OAAIOAI 
       ?OE AIIOUEE IO?AOAE.

    *) eO?OA?IAIEA: IOOOOOO?EA OOOIEE UACIII?EA "Referer" ?OACAA O?EOAIIOO 
       ?OA?EIOIUI referrer'II.


eUIAIAIEN ? nginx 0.1.23                                          01.03.2005

    *) aIAA?IAIEA: IIAOIO ngx_http_ssi_filter_module E AEOAEOE?U ssi, 
       ssi_silent_errors E ssi_min_file_chunk. ?IAAAOOE?AAOON EIIAIAU 'echo 
       var="HTTP_..." default=""' E 'echo var="REMOTE_ADDR"'.

    *) aIAA?IAIEA: ?AOAIAOO IICA %request_time.

    *) aIAA?IAIEA: AOIE UA?OIO ?OEU?I AAU OOOIEE UACIII?EA "Host", OI 
       AEOAEOE?A proxy_preserve_host OOOAIA?IE?AAO ? EA?AOO?A UOICI 
       UACIII?EA ?AO?IA EIN OAO?AOA EU AEOAEOE?U server_name.

    *) eO?OA?IAIEA: nginx IA OIAEOAION IA ?IAO?IOIAE, IOIE?IUE IO i386, 
       amd64, sparc E ppc; IUEAEA ?IN?EIAOO ? 0.1.22.

    *) eO?OA?IAIEA: IIAOIO ngx_http_autoindex_module OA?AOO ?IEAUU?AAO 
       EI?IOIAAEA IA I OEI?IIE?AOEII IEIEA, A I ?AEIA EIE EAOAIICA, IA 
       EIOIOUE II OEAUU?AAO.

    *) eO?OA?IAIEA: AOIE EIEAIOO IE?ACI IA ?AOAAA?AIIOO, OI ?AOAIAOO 
       %apache_length UA?EOU?AI ? IIC IOOEAAOAIOIOA AIEIO UACIII?EA IO?AOA.


eUIAIAIEN ? nginx 0.1.22                                          22.02.2005

    *) eO?OA?IAIEA: IIAOIO ngx_http_stub_status_module ?IEAUU?AI IA?AOIOA 
       OOAOEOOEEO AIN IAOAAIOAIIUE OIAAEIAIEE, AOIE EO?IIOUI?AIIOO 
       ?OIEOEOI?AIEA EIE FastCGI-OAO?AO.

    *) eO?OA?IAIEA: IA Linux E Solaris OOOAII?I?IUA ?OOE AUIE IA?AOII 
       UAEIA?AIU ? EA?U?EE; IUEAEA ?IN?EIAOO ? 0.1.21.


eUIAIAIEN ? nginx 0.1.21                                          22.02.2005

    *) eO?OA?IAIEA: IIAOIO ngx_http_stub_status_module ?IEAUU?AI IA?AOIOA 
       OOAOEOOEEO ?OE EO?IIOUI?AIEE IAOIAA rtsig EIE ?OE EO?IIOUI?AIEE 
       IAOEIIOEEE OAAI?EE ?OIAAOOI? IA SMP IAUEIA.

    *) eO?OA?IAIEA: nginx IA OIAEOAION EII?EINOIOII icc ?IA iEIOEOII EIE 
       AOIE AEAIEIOAEA zlib-1.2.x OIAEOAIAOO EU EOEIAIUE OAEOOI?.

    *) eO?OA?IAIEA: nginx IA OIAEOAION ?IA NetBSD 2.0.


eUIAIAIEN ? nginx 0.1.20                                          17.02.2005

    *) aIAA?IAIEA: II?UA ?AOAIAOOU script_filename E remote_port ? 
       AEOAEOE?A fastcgi_params.

    *) eO?OA?IAIEA: IA?OA?EIOII IAOAAAOU?AION ?IOIE stderr IO 
       FastCGI-OAO?AOA.


eUIAIAIEN ? nginx 0.1.19                                          16.02.2005

    *) eO?OA?IAIEA: AOIE ? UA?OIOA AOOO IOIO, OI AIN IIEAIOIUE UA?OIOI? 
       OA?AOO ?IU?OAYAAOON IUEAEA 404.

    *) eO?OA?IAIEA: nginx IA OIAEOAION ?IA NetBSD 2.0.

    *) eO?OA?IAIEA: ?I ?OAIN ?OAIEN OAIA UA?OIOA EIEAIOA ? SSL OIAAEIAIEE 
       IIC ?OIEUIEOE OAEIAOO.


eUIAIAIEN ? nginx 0.1.18                                          09.02.2005

    *) eUIAIAIEA: AIN OI?IAOOEIIOOE O Solaris 10 ? AEOAEOE?AE 
       devpoll_events E devpoll_changes UIA?AIEN ?I OIII?AIEA OIAIOUAIU O 
       512 AI 32.

    *) eO?OA?IAIEA: AEOAEOE?U proxy_set_x_var E fastcgi_set_var IA 
       IAOIAAI?AIEOO.

    *) eO?OA?IAIEA: ? AEOAEOE?A rewrite, ?IU?OAYAAYAE OAAEOAEO, AOCOIAIOU 
       ?OEOIAAEINIEOO E URI ?AOAU OEI?II "&" ?IAOOI "?".

    *) eO?OA?IAIEA: OOOIEE AIN IIAOIN ngx_http_geo_module AAU OEI?IIA ";" 
       ?I ?EIA??IIII ?AEIA ECIIOEOI?AIEOO.

    *) aIAA?IAIEA: IIAOIO ngx_http_stub_status_module.

    *) eO?OA?IAIEA: IAEU?AOOIUE ?IOIAO IIC-?AEIA ? AEOAEOE?A access_log 
       ?UUU?AI segmentation fault.

    *) aIAA?IAIEA: II?UE ?AOAIAOO document_root ? AEOAEOE?A fastcgi_params.

    *) aIAA?IAIEA: AEOAEOE?A fastcgi_redirect_errors.

    *) aIAA?IAIEA: II?UE IIAE?EEAOIO break ? AEOAEOE?A rewrite ?IU?IINAO 
       ?OAEOAOEOO AEEI rewrite/location E OOOAIA?IE?AAO OAEOYOA 
       EII?ECOOAAEA AIN UA?OIOA.


eUIAIAIEN ? nginx 0.1.17                                          03.02.2005

    *) eUIAIAIEA: IIAOIO ngx_http_rewrite_module ?IIIIOOOA ?AOA?EOAI. 
       oA?AOO IIOII AAIAOO OAAEOAEOU, ?IU?OAYAOO EIAU IUEAIE E ?OI?AONOO 
       ?AOAIAIIUA E OA?AOAOU. uOE AEOAEOE?U IIOII EO?IIOUI?AOO ?IOOOE 
       location. aEOAEOE?A redirect O?OAUAIAIA.

    *) aIAA?IAIEA: IIAOIO ngx_http_geo_module.

    *) aIAA?IAIEA: AEOAEOE?U proxy_set_x_var E fastcgi_set_var.

    *) eO?OA?IAIEA: EII?ECOOAAEN location O IIAE?EEAOIOII "=" IICIA 
       EO?IIOUI?AOOON ? AOOCII location.

    *) eO?OA?IAIEA: ?OA?EIOIUE OE? IO?AOA ?UOOA?INION OIIOEI AIN UA?OIOI?, 
       O EIOIOUE ? OAOUEOAIEE AUIE OIIOEI IAIAIOEEA AOE?U.

    *) eO?OA?IAIEA: AOIE AIN location OOOAII?IAI proxy_pass EIE 
       fastcgi_pass, E AIOOO? E IAIO UA?OAYAION, A IUEAEA ?AOAIA?OA?INIAOO 
       IA OOAOE?AOEOA OOOAIEAO, OI ?OIEOEIAEI segmentation fault.

    *) eO?OA?IAIEA: AOIE ? ?OIEOEOI?AIIII IO?AOA ? UACIII?EA "Location" 
       ?AOAAA?AION IOIIOEOAIOIUE URL, OI E IAIO AIAA?INIIOO EIN EIOOA E 
       OIUU; IUEAEA ?IN?EIAOO ? 0.1.14.

    *) eO?OA?IAIEA: IA Linux ? IIC IA UA?EOU?AION OAEOO OEOOAIIIE IUEAEE.


eUIAIAIEN ? nginx 0.1.16                                          25.01.2005

    *) eO?OA?IAIEA: AOIE IO?AO ?AOAAA?AION chunk'AIE, OI ?OE UA?OIOA HEAD 
       ?UAA?AION UA?AOUAAYEE chunk.

    *) eO?OA?IAIEA: UACIII?IE "Connection: keep-alive" ?UAA?AION, AAOA AOIE 
       AEOAEOE?A keepalive_timeout UA?OAYAIA EO?IIOUI?AIEA keep-alive.

    *) eO?OA?IAIEA: IUEAEE ? IIAOIA ngx_http_fastcgi_module ?UUU?AIE 
       segmentation fault.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE SSL OOAOUE IO?AO IIC ?AOAAA?AOOON IA 
       AI EIIAA.

    *) eO?OA?IAIEA: I?AEE TCP_NODELAY, TCP_NOPSUH E TCP_CORK, O?AAE?E?IUA 
       AIN TCP OIEAOI?, IA EO?IIOUOAOON AIN unix domain OIEAOI?.

    *) aIAA?IAIEA: AEOAEOE?A rewrite ?IAAAOOE?AAO ?AOAUA?EOU?AIEA 
       AOCOIAIOI?.

    *) eO?OA?IAIEA: IA UA?OIO POST O UACIII?EII "Content-Length: 0" 
       ?IU?OAYAION IO?AO 400; IUEAEA ?IN?EIAOO ? 0.1.14.


eUIAIAIEN ? nginx 0.1.15                                          19.01.2005

    *) eO?OA?IAIEA: IUEAEA OIAAEIAIEN O FastCGI-OAO?AOII ?UUU?AIA 
       segmentation fault.

    *) eO?OA?IAIEA: EIOOAEOIAN IAOAAIOEA OACOINOIICI ?UOAOAIEN, ? EIOIOII 
       ?EOII ?UAAIAIIUE ?AOOAE IA OI??AAAAO O ?EOIII ?IAOOAII?IE.

    *) aIAA?IAIEA: location, EIOIOUE ?AOAAA?OON FastCGI-OAO?AOO, IIOAO AUOO 
       UAAAI O ?IIIYOA OACOINOIICI ?UOAOAIEN.

    *) eO?OA?IAIEA: ?AOAIAOO FastCGI REQUEST_URI OA?AOO ?AOAAA?OON ?IAOOA O 
       AOCOIAIOAIE E ? OII ?EAA, ? EIOIOII AUI ?IIO?AI IO EIEAIOA.

    *) eO?OA?IAIEA: AIN EO?IIOUI?AIEN OACOINOIUE ?UOAOAIEE ? location IOOII 
       AUII OIAEOAOO nginx ?IAOOA O ngx_http_rewrite_module.

    *) eO?OA?IAIEA: AOIE AUEAIA OIOUAI IA 80-II ?IOOO, OI ?OE EO?IIOUI?AIEE 
       AEOAEOE?U "proxy_preserve_host  on" ? UACIII?EA "Host" OEAUU?AION 
       OAEOA ?IOO 80; IUEAEA ?IN?EIAOO ? 0.1.14.

    *) eO?OA?IAIEA: AOIE UAAAOO IAEIAEI?UA ?OOE ? ?AOAIAOOAE 
       A?OIEII?ECOOAAEE --http-client-body-temp-path=PATH E 
       --http-proxy-temp-path=PATH EIE --http-client-body-temp-path=PATH E 
       --http-fastcgi-temp-path=PATH, OI ?OIEOEIAEI segmentation fault.


eUIAIAIEN ? nginx 0.1.14                                          18.01.2005

    *) aIAA?IAIEA: ?AOAIAOOU A?OIEII?ECOOAAEE 
       --http-client-body-temp-path=PATH, --http-proxy-temp-path=PATH E 
       --http-fastcgi-temp-path=PATH

    *) eUIAIAIEA: EIN EAOAIICA O ?OAIAIIUIE ?AEIAIE, OIAAOOAYEA OAII 
       UA?OIOA EIEAIOA, UAAA?OON AEOAEOE?IE client_body_temp_path, ?I 
       OIII?AIEA <prefix>/client_body_temp.

    *) aIAA?IAIEA: IIAOIO ngx_http_fastcgi_module E AEOAEOE?U fastcgi_pass, 
       fastcgi_root, fastcgi_index, fastcgi_params, 
       fastcgi_connect_timeout, fastcgi_send_timeout, fastcgi_read_timeout, 
       fastcgi_send_lowat, fastcgi_header_buffer_size, fastcgi_buffers, 
       fastcgi_busy_buffers_size, fastcgi_temp_path, 
       fastcgi_max_temp_file_size, fastcgi_temp_file_write_size, 
       fastcgi_next_upstream E fastcgi_x_powered_by.

    *) eO?OA?IAIEA: IUEAEA "[alert] zero size buf"; IUEAEA ?IN?EIAOO ? 
       0.1.3.

    *) eUIAIAIEA: ? AEOAEOE?A proxy_pass IOOII IANUAOAIOII OEAUU?AOO URI 
       ?IOIA EIAIE EIOOA.

    *) eUIAIAIEA: AOIE ? URI ?OOOA?AION OEI?II %3F, OI II O?EOAION IA?AIII 
       OOOIEE AOCOIAIOI?.

    *) aIAA?IAIEA: ?IAAAOOEA unix domain OoEAOI? ? IIAOIA 
       ngx_http_proxy_module.

    *) aIAA?IAIEA: AEOAEOE?U ssl_engine E ssl_ciphers.
       o?AOEAI oAOCAA oE?IOAI?O UA SSL-AEOAIAOAOIO.


eUIAIAIEN ? nginx 0.1.13                                          21.12.2004

    *) aIAA?IAIEA: AEOAEOE?U server_names_hash E 
       server_names_hash_threshold.

    *) eO?OA?IAIEA: EIAIA *.domain.tld ? AEOAEOE?A server_name IA OAAIOAIE.

    *) eO?OA?IAIEA: ?AOAIAOO IICA %request_length UA?EOU?AI IA?AOIOA AIEIO.


eUIAIAIEN ? nginx 0.1.12                                          06.12.2004

    *) aIAA?IAIEA: ?AOAIAOO IICA %request_length.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE /dev/poll, select E poll IA 
       ?IAO?IOIAE, CAA ?IUIIOIU IIOIUA OOAAAOU?AIEN OEAUAIIUE IAOIAI?, 
       IICIE AUOO AIEOAIOIUA UAAAOOEE ?OE IAOAAIOEA UA?OIOA ?I keep-alive 
       OIAAEIAIEA. iAAIAAAIIOO ?I EOAEIAE IAOA IA Solaris O EO?IIOUI?AIEAI 
       /dev/poll.

    *) eO?OA?IAIEA: AEOAEOE?A send_lowat ECIIOEOOAOON IA Linux, OAE EAE 
       Linux IA ?IAAAOOE?AAO I?AEA SO_SNDLOWAT.


eUIAIAIEN ? nginx 0.1.11                                          02.12.2004

    *) aIAA?IAIEA: AEOAEOE?A worker_priority.

    *) eUIAIAIEA: ?IA FreeBSD AEOAEOE?U tcp_nopush E tcp_nodelay ?IAOOA 
       ?IENAO IA ?AOAAA?O IO?AOA.

    *) eO?OA?IAIEA: nginx IA ?UUU?AI initgroups().
       o?AOEAI aIAOAA oEOIEEI?O E aIAOAA iECIAOOIEIO.

    *) eUIAIAIEA: ngx_http_auto_index_module OA?AOO ?UAA?O OAUIAO ?AEII? ? 
       AAEOAE.

    *) eO?OA?IAIEA: ngx_http_auto_index_module ?IU?OAYAI IUEAEO 500, AOIE ? 
       EAOAIICA AOOO AEOUE symlink.

    *) eO?OA?IAIEA: ?AEIU AIIOUA 4G IA ?AOAAA?AIEOO O EO?IIOUI?AIEAI 
       sendfile.

    *) eO?OA?IAIEA: AOIE AUEAIA OAUII?EION ? IAOEIIOEI AAOAOI? E ?OE 
       IOEAAIEE IO IACI IO?AOA ?OIEOEIAEIA IUEAEA, OI ?OIAAOO UAAEEIE?AION.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE IAOIAA /dev/poll OAAI?EE ?OIAAOO IIC 
       UA?AOUEOOON O OIIAYAIEAI "unknown cycle".

    *) eO?OA?IAIEA: IUEAEE "close() channel failed".

    *) eO?OA?IAIEA: A?OIIAOE?AOEIA I?OAAAIAIEA COO?? nobody E nogroup.

    *) eO?OA?IAIEA: AEOAEOE?A send_lowat IA OAAIOAIA IA Linux.

    *) eO?OA?IAIEA: AOIE ? EII?ECOOAAEE IA AUII OAUAAIA events, OI 
       ?OIEOEIAEI segmentation fault.

    *) eO?OA?IAIEA: nginx IA OIAEOAION ?IA OpenBSD.

    *) eO?OA?IAIEA: A?IEIUA OIUUU ? "://" ? URI ?OA?OAYAIEOO ? ":/".


eUIAIAIEN ? nginx 0.1.10                                          26.11.2004

    *) eO?OA?IAIEA: AOIE ? UA?OIOA AAU AOCOIAIOI? AOOO "//", "/./", "/../" 
       EIE "%XX", OI OAONION ?IOIAAIEE OEI?II ? OOOIEA UA?OIOA; IUEAEA 
       ?IN?EIAOO ? 0.1.9.

    *) eO?OA?IAIEA: EO?OA?IAIEA ? ?AOOEE 0.1.9 AIN ?AEII? AIIOUA 2G IA 
       Linux IA OAAIOAII.


eUIAIAIEN ? nginx 0.1.9                                           25.11.2004

    *) eO?OA?IAIEA: AOIE ? UA?OIOA AOOO "//", "/./", "/../" EIE "%XX", OI 
       ?OIEOEOOAIUE UA?OIO ?AOAAA?AION AAU AOCOIAIOI?.

    *) eO?OA?IAIEA: ?OE OOAOEE AIIOUEE IO?AOI? EIICAA IIE ?AOAAA?AIEOO IA 
       ?IIIIOOOA.

    *) eO?OA?IAIEA: IA ?AOAAA?AIEOO ?AEIU AIIOUA 2G IA Linux, 
       IA?IAAAOOE?AAYAI sendfile64().

    *) eO?OA?IAIEA: IA Linux ?OE EII?ECOOAAEE OAIOEE IOOII AUII IANUAOAIOII 
       EO?IIOUI?AOO ?AOAIAOO --with-poll_module; IUEAEA ?IN?EIAOO ? 0.1.8.


eUIAIAIEN ? nginx 0.1.8                                           20.11.2004

    *) eO?OA?IAIEA: IUEAEA ? IIAOIA ngx_http_autoindex_module ?OE ?IEAUA 
       AIEIIUE EI?I ?AEII?.

    *) aIAA?IAIEA: IIAE?EEAOIO "^~" ? AEOAEOE?A location.

    *) aIAA?IAIEA: AEOAEOE?A proxy_max_temp_file_size.


eUIAIAIEN ? nginx 0.1.7                                           12.11.2004

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE sendfile, AOIE ?AOAAA?AAIUE ?AEI 
       IAINION, OI IIC ?OIEUIEOE segmentation fault IA FreeBSD; IUEAEA 
       ?IN?EIAOO ? 0.1.5.


eUIAIAIEN ? nginx 0.1.6                                           11.11.2004

    *) eO?OA?IAIEA: ?OE IAEIOIOUE EIIAEIAAENE AEOAEOE? location c 
       OACOINOIUIE ?UOAOAIENIE EO?IIOUI?AIAOO EII?ECOOAAEN IA EU OICI 
       location.


eUIAIAIEN ? nginx 0.1.5                                           11.11.2004

    *) eO?OA?IAIEA: IA Solaris E Linux IICII AUOO I?AIO IIICI OIIAYAIEE 
       "recvmsg() returned not enough data".

    *) eO?OA?IAIEA: ? OAOEIA ?OIEOE AAU EO?IIOUI?AIEN sendfile IA Solaris 
       ?IUIEEAIA IUEAEA "writev() failed (22: Invalid argument)". iA AOOCEE 
       ?IAO?IOIAE, IA ?IAAAOOE?AAYEE sendfile, ?OIAAOO UAAEEIE?AION.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE sendfile ? OAOEIA ?OIEOE IA Solaris 
       ?IUIEEAI segmentation fault.

    *) eO?OA?IAIEA: segmentation fault IA Solaris.

    *) eO?OA?IAIEA: IAII?IAIEA EO?IIINAIICI ?AEIA IA IAOO IA OAAIOAII IA 
       Linux.

    *) eO?OA?IAIEA: ? O?EOEA ?AEII?, ?UAA?AAIII IIAOIAI 
       ngx_http_autoindex_module, IA ?AOAEIAEOI?AIEOO ?OIAAIU, EA?U?EE E 
       UIAEE ?OIAAIOA.

    *) eUIAIAIEA: OIAIOUAIEA I?AOAAEE EI?EOI?AIEN.

    *) aIAA?IAIEA: AEOAEOE?A userid_p3p.


eUIAIAIEN ? nginx 0.1.4                                           26.10.2004

    *) eO?OA?IAIEA: IUEAEA ? IIAOIA ngx_http_autoindex_module.


eUIAIAIEN ? nginx 0.1.3                                           25.10.2004

    *) aIAA?IAIEA: IIAOIO ngx_http_autoindex_module E AEOAEOE?A autoindex.

    *) aIAA?IAIEA: AEOAEOE?A proxy_set_x_url.

    *) eO?OA?IAIEA: IIAOIO ?OIEOEOI?AIEE IIC ?OE?AOOE E UAAEEIE?AIEA, AOIE 
       IA EO?IIOUI?AION sendfile.


eUIAIAIEN ? nginx 0.1.2                                           21.10.2004

    *) aIAA?IAIEA: ?AOAIAOOU --user=USER, --group=GROUP E 
       --with-ld-opt=OPTIONS ? configure.

    *) aIAA?IAIEA: AEOAEOE?A server_name ?IAAAOOE?AAO *.domain.tld.

    *) eO?OA?IAIEA: OIO?UAIA ?AOAIIOEIIOOO IA IAEU?AOOIUA ?IAO?IOIU.

    *) eO?OA?IAIEA: IAIOUN ?AOAEII?ECOOEOI?AOO nginx, AOIE EII?ECOOAAEIIIUE 
       ?AEI OEAUAI ? EIIAIAIIE OOOIEA; IUEAEA ?IN?EIAOO ? 0.1.1.

    *) eO?OA?IAIEA: IIAOIO ?OIEOEOI?AIEE IIC ?OE?AOOE E UAAEEIE?AIEA, AOIE 
       IA EO?IIOUI?AION sendfile.

    *) eO?OA?IAIEA: ?OE EO?IIOUI?AIEE sendfile OAEOO IO?AOA IA 
       ?AOAEIAEOI?AION OICIAOII AEOAEOE?AI IIAOIN charset; IUEAEA ?IN?EIAOO 
       ? 0.1.1.

    *) eO?OA?IAIEA: I?AIO OAAEAN IUEAEA ?OE IAOAAIOEA kqueue.

    *) eO?OA?IAIEA: IIAOIO OOAOEN OOEIAI OOA OOAOUA IO?AOU, ?IIO?AIIUA ?OE 
       ?OIEOEOI?AIEE.


eUIAIAIEN ? nginx 0.1.1                                           11.10.2004

    *) aIAA?IAIEA: AEOAEOE?A gzip_types.

    *) aIAA?IAIEA: AEOAEOE?A tcp_nodelay.

    *) aIAA?IAIEA: AEOAEOE?A send_lowat OAAIOAAO IA OIIOEI IA ?IAO?IOIAE, 
       ?IAAAOOE?AAYEE kqueue NOTE_LOWAT, II E IA ?OAE, ?IAAAOOE?AAYEE 
       SO_SNDLOWAT.

    *) aIAA?IAIEA: UIOINAEN setproctitle() AIN Linux E Solaris.

    *) eO?OA?IAIEA: IUEAEA ?OE ?AOA?EOU?AIEE UACIII?EA "Location" ?OE 
       ?OIEOEOI?AIEE.

    *) eO?OA?IAIEA: IUEAEA ? IIAOIA ngx_http_chunked_module, ?OE?IAE?UAN E 
       UAAEEIE?AIEA.

    *) eO?OA?IAIEA: IUEAEE ? IIAOIA /dev/poll.

    *) eO?OA?IAIEA: ?OE ?OIEOEOI?AIEE E EO?IIOUI?AIEE ?OAIAIIUE ?AEII? 
       IO?AOU ?IOOEIEOO.

    *) eO?OA?IAIEA: AUEAIAO ?AOAAA?AIEOO UA?OIOU O IA?AOAEIAEOI?AIIUIE 
       OEI?IIAIE.

    *) eO?OA?IAIEA: IA Linux 2.4 ?OE EII?ECOOAAEE OAIOEE IOOII AUII 
       IANUAOAIOII EO?IIOUI?AOO ?AOAIAOO --with-poll_module.


eUIAIAIEN ? nginx 0.1.0                                           04.10.2004

    *) ?AO?AN ?OAIE?II AIOOO?IAN ?AOOEN.

