// ==UserScript==
// @name         Smart Proxy System - Advanced
// @namespace    http://tampermonkey.net/
// @version      2.4
// @description  Gelişmiş akıllı proxy yönlendirme sistemi - engellenen sitelere otomatik erişim
// @author       You
// @match        *
// @connect      *
// @grant        GM_xmlhttpRequest
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_deleteValue
// @grant        GM_listValues
// @grant        GM_addValueChangeListener
// @grant        GM_notification
// @run-at       document-start
// ==/UserScript==

!function() {
    'use strict';
    
    // ====================================
    // GLOBAL KONFIGÜRASYON
    // ====================================
    
    const CONFIG = {
        // Proxy sunucuları - yük dengeleme ve failover için
        PROXY_URLS: [
    'https://fragrant-dream-fc59.mehmet-arikan.workers.dev'
],
        
        // Zamanlayıcı ayarları
        DNS_CHECK_INTERVAL: 5000,
        AVAILABILITY_CHECK_INTERVAL: 24 * 60 * 60 * 1000, // 1 gün
        RETRY_DELAY: 2000,
        CONTENT_UPDATE_THROTTLE: 100,
        
        // Kontrol parametreleri
        AUTO_CHECK_AVAILABILITY: true,
        MAX_RETRY_ATTEMPTS: 3,
        REQUEST_TIMEOUT: 15000,
        
        // Engel tespiti için belirteçler
        BLOCKED_INDICATORS: [
            'erişime engellenmiştir',
            'BTK',
            'Bilgi Teknolojileri ve İletişim Kurumu',
            'has been blocked',
            'İnternet Erişimine Engellenmiştir',
            'Bu internet sitesi hakkında',
            'Site Engellendi',
            'Access Denied',
            'Blocked by',
            'İçerik Engellenmiştir',
            'Yasaklı Site',
            'Banned Site',
            'Restricted Access'
        ],
        
        // Öntanımlı engellenen domainler
        DEFAULT_BLOCKED_DOMAINS: [
            // Mevcut liste burada kalacak
            '26efp.com', 'abgay.com', 'ahcdn.abgay.tube', 'ahcdn.com', 'all3do.com', 'assets-cdn.porn.com', 'bi.phncdn.com', 'boyfriendtv.com', 'boyfriendtv3.com', 'cast.freepornvideos.xxx', 'cbn.pornxp.cc', 'cc.boyfriendtv.com', 'cdn-centaurus.com', 'cdn-img1.playvids.com', 'cdn.boyfriendtv.com', 'cdn1-smallimg.phncdn.com', 'cdn1d-static-shared.phncdn.com', 'cdn1d-static-shared.phncdn.com.sds.rncdn7.com', 'cdn255.com', 'cdn77-pic.xvideos-cdn.com', 'cdn77-t.boyfriendtv.com', 'cdn77-vid-mp4.xvideos-cdn.com', 'cdn77-vid.xvideos-cdn.com', 'cdn77.boyfriend.tv', 'cdn77.boyfriendstar.com', 'cdn77.boyfriendtv.com', 'cdnstream.top', 'cdrn.pornxp.cc', 'cloudatacdn.com', 'cockdude.com', 'd000d.com', 'daly2024.com', 'dhcplay.com', 'do0od.com', 'do7go.com', 'dood.pm', 'dood.re', 'dood.sh', 'doodstream.com', 'dooodster.com', 'doply.net', 'ei.phncdn.com', 'ei.phncdn.com.sds.rncdn7.com', 'em-h.phncdn.com', 'em.phncdn.com', 'eporner.com', 'eu-west-3.xhamster.com', 'ev-h.phncdn.com', 'ew.phncdn.com', 'ew.phncdn.com.sds.rncdn7.com', 'fallback.xhamster.com', 'filemoon.to', 'fpvcdn.com', 'freepornvideos.xxx', 'fxggxt.com', 'gay-top.net', 'gayfuckporn.com', 'gaygo.tv', 'gaymaletube.com', 'gayporn.video', 'gaytube.site', 'gcore-pic.xvideos-cdn.com', 'gcore-vid.xvideos-cdn.com', 'gfroshrvfusqpt.com', 'go.xlivrdr.com', 'hcaptcha.com', 'hdcdn.site', 'hdgaytube.xxx', 'hutgay.com', 'i.doodcdn.io', 'i.pornxp.cc', 'i8yz83pn.com', 'ic-ph-nss.xhcdn.com', 'ic-st-nss.xhcdn.com', 'ic-tt-nss.xhcdn.com', 'ic-ut-nss.xhcdn.com', 'ic-vrm-nss.xhcdn.com', 'ic-vt-nss.xhcdn.com', 'icdn05.boy18tube.com', 'icdn05.gayfuckporn.com', 'icdn05.icegaytube.tv', 'icdn05.igayporn.tv', 'icdn05.machotube.tv', 'icegay.tv', 'icegaytube.tv', 'igayporn.tv', 'ii.abgay.org', 'im-h.phncdn.com', 'imageproxy.eu.criteo.net', 'img.doodcdn.io', 'img.freepornvideos.xxx', 'j.pornxp.cc', 'jilliandescribecompany.com', 'join.latinleche.com', 'kv-h.phncdn.com', 'l.pornxp.cc', 'lethimhit.com', 'likegay.net', 'machotube.tv', 'manporn.xxx', 'media.daly2024.com', 'mensporn.org', 'mrgay.com', 'mundoxgay.com', 'mygaysites.com', 'onlybussy.com', 'pastebin.com', 'picstate.com', 'pictures-cdn.porn.com', 'playvids.com', 'pornhub.com', 'pornone.com', 'pornxp.com', 'pornxp.stream', 'profile-pics-cdn77.xvideos-cdn.com', 'proton.me', 'protonvpn.com', 'proxy-skadnetwork.apple.com', 'redir.pornxp.cc', 'reports.proton.me', 'sf.pornxp.cc', 'sh.pornxp.cc', 'sj.pornxp.cc', 'sl.pornxp.cc', 'smallimg.phncdn.com', 'srv.daly2024.com', 'ss.phncdn.com', 'ss.phncdn.com.sds.rncdn7.com', 'static-ah.xhcdn.com', 'static-cdn77.xvideos-cdn.com', 'static-nss.xhcdn.com', 'static2.mpxcdn.com', 'strcdn.icu', 'stripchat.ooo', 'strp.chat', 't.pornxp.cc', 'th-02.mpxcdn.com', 'thegay.com', 'thumb-nss.xhcdn.com', 'thumb-v0.xhcdn.com', 'thumb-v1.xhcdn.com', 'thumb-v2.xhcdn.com', 'thumb-v3.xhcdn.com', 'thumb-v4.xhcdn.com', 'thumb-v5.xhcdn.com', 'thumb-v6.xhcdn.com', 'thumb-v7.xhcdn.com', 'thumb-v8.xhcdn.com', 'thumb-v9.xhcdn.com', 'topcdn.site', 'tr.gayfuckporn.com', 'tr.icegaytube.tv', 'tr.igayporn.tv', 'tr.machotube.tv', 'tr.xhamster.com', 'tube8.com', 'turbogvideos.com', 'u3.boy18tube.com', 'u3.machotube.tv', 'us-west-1.xhamster.com', 'userscontent.net', 'vcdn.freepornvideos.xxx', 'vcdn.mengem.com', 'vcdn03.boy18tube.com', 'vcdn03.gayfuckporn.com', 'vcdn03.igayporn.tv', 'vcdn03.machotube.tv', 'vcdn1.gayck.com', 'vcdn2.gayck.com', 'vide0.net', 'video-a.xhcdn.com', 'video-b.xhcdn.com', 'video-cf-a.xhcdn.com', 'video-cf-b.xhcdn.com', 'video-cf.xhcdn.com', 'video.sissyflix.com', 'video7.xhcdn.com', 'videothumbs.me', 'vidply.com', 'vpncdn.protonweb.com', 'vv.abgay.org', 'vv2.abgay.org', 'vv3.abgay.org', 'w.pornxp.cc', 'ww1.hutgay.com', 'www.4gay.com', 'www.5gays.com', 'www.boy18tube.com', 'www.boyfriendtv.com', 'www.eporner.com', 'www.freepornvideos.xxx', 'www.fxggxt.com', 'www.gayck.com', 'www.gayfuckporn.com', 'www.gaymaletube.com', 'www.icegay.tv', 'www.icegaytube.tv', 'www.igayporn.tv', 'www.kcadxjoxkggcui.com', 'www.latinleche.com', 'www.lovetransex.com', 'www.machotube.tv', 'www.mengem.com', 'www.onlygayvideo.com', 'www.playvids.com', 'www.porn.com', 'www.pornhub.com', 'www.sissyflix.com', 'www.tube8.com', 'www.xvideos.com', 'www.yeswegays.com', 'www.yuntodifrz.com', 'xhcdn.com', 'xvideos.com', 'xvidgay.com'
        ],
        
        // Hata ayıklama ve performans
        DEBUG: true,
        PERFORMANCE_MONITORING: true,
        
        // Güvenlik ayarları
        ALLOWED_PROTOCOLS: ['http:', 'https:'],
        BLOCKED_EXTENSIONS: ['.exe', '.bat', '.cmd', '.scr', '.msi'],
        
        // UI ayarları
        UI_ENABLED: true,
        UI_POSITION: 'bottom-right',
        UI_THEME: 'auto' // 'light', 'dark', 'auto'
    };

    // ====================================
    // YARDIMCI FONKSİYONLAR
    // ====================================
    
    const Utils = {
        // Performans izleme
        performanceData: new Map(),
        
        // Throttle ve debounce için
        throttleMap: new Map(),
        debounceMap: new Map(),
        
        /**
         * Gelişmiş loglama sistemi
         */
        log(level, message, data = null) {
            if (!CONFIG.DEBUG) return;
            
            const timestamp = new Date().toISOString();
            const prefix = `[SmartProxy][${level}][${timestamp}]`;
            
            switch (level) {
                case 'ERROR':
                    console.error(prefix, message, data);
                    break;
                case 'WARN':
                    console.warn(prefix, message, data);
                    break;
                case 'INFO':
                    console.info(prefix, message, data);
                    break;
                case 'DEBUG':
                    console.debug(prefix, message, data);
                    break;
                default:
                    console.log(prefix, message, data);
            }
        },
        
        /**
         * Performans ölçümü
         */
        startPerformance(key) {
            if (!CONFIG.PERFORMANCE_MONITORING) return;
            this.performanceData.set(key, performance.now());
        },
        
        endPerformance(key) {
            if (!CONFIG.PERFORMANCE_MONITORING) return;
            const startTime = this.performanceData.get(key);
            if (startTime) {
                const duration = performance.now() - startTime;
                this.log('DEBUG', `Performance: ${key} took ${duration.toFixed(2)}ms`);
                this.performanceData.delete(key);
            }
        },
        
        /**
         * Throttle fonksiyonu
         */
        throttle(func, delay, key) {
            if (this.throttleMap.has(key)) {
                return;
            }
            
            this.throttleMap.set(key, true);
            func();
            
            setTimeout(() => {
                this.throttleMap.delete(key);
            }, delay);
        },
        
        /**
         * Debounce fonksiyonu
         */
        debounce(func, delay, key) {
            if (this.debounceMap.has(key)) {
                clearTimeout(this.debounceMap.get(key));
            }
            
            const timeoutId = setTimeout(() => {
                func();
                this.debounceMap.delete(key);
            }, delay);
            
            this.debounceMap.set(key, timeoutId);
        },
        
        /**
         * Gelişmiş URL işleme
         */
        normalizeUrl(url) {
            if (!url || typeof url !== 'string') return '';
            
            try {
                // Relative URL'leri absolute yapma
                if (url.startsWith('//')) {
                    url = window.location.protocol + url;
                } else if (url.startsWith('/')) {
                    url = window.location.origin + url;
                }
                
                const urlObj = new URL(url);
                
                // Protokol kontrolü
                if (!CONFIG.ALLOWED_PROTOCOLS.includes(urlObj.protocol)) {
                    return '';
                }
                
                // Güvenlik kontrolü
                const pathname = urlObj.pathname.toLowerCase();
                if (CONFIG.BLOCKED_EXTENSIONS.some(ext => pathname.endsWith(ext))) {
                    return '';
                }
                
                return urlObj.href;
            } catch (e) {
                this.log('WARN', 'URL normalize hatası:', e);
                return '';
            }
        },
        
        /**
         * Domain normalizasyonu
         */
        normalizeDomain(domain) {
            if (!domain || typeof domain !== 'string') return '';
            
            return domain.toLowerCase()
                .replace(/^https?:\/\//, '')
                .replace(/^www\./, '')
                .replace(/\/$/, '')
                .split('/')[0]
                .split('?')[0]
                .split('#')[0];
        },
        
        /**
         * Domain eşleştirme
         */
        domainMatches(hostname, domain) {
            const normalizedHostname = this.normalizeDomain(hostname);
            const normalizedDomain = this.normalizeDomain(domain);
            
            return normalizedHostname === normalizedDomain || 
                   normalizedHostname.endsWith('.' + normalizedDomain) ||
                   normalizedDomain.endsWith('.' + normalizedHostname);
        },
        
        /**
         * Proxy URL oluşturma
         */
        createProxyUrl(originalUrl, proxyBaseUrl) {
    // Eğer zaten proxyBaseUrl ile başlamışsa, yeniden proxy’leme
    if (originalUrl.startsWith(proxyBaseUrl)) return originalUrl;

    const normalizedUrl = this.normalizeUrl(originalUrl);
    if (!normalizedUrl) return originalUrl;
    // … geri kalan kod aynı kalsın
    let proxyUrl = `${proxyBaseUrl}/${normalizedUrl}`;
    if (window.location.href.includes('&view=')) {
        proxyUrl += window.location.href.match(/&view=[^&]*/)[0];
    }
    return proxyUrl;
},
        
        /**
         * Rastgele proxy seçimi
         */
        selectRandomProxy() {
            const availableProxies = [...CONFIG.PROXY_URLS];
            const randomIndex = Math.floor(Math.random() * availableProxies.length);
            return availableProxies[randomIndex];
        },
        
        /**
         * Async sleep
         */
        sleep(ms) {
            return new Promise(resolve => setTimeout(resolve, ms));
        },
        
        /**
         * Güvenli JSON parse
         */
        safeJsonParse(jsonString, defaultValue = null) {
            try {
                return JSON.parse(jsonString);
            } catch (e) {
                this.log('WARN', 'JSON parse hatası:', e);
                return defaultValue;
            }
        },
        
        /**
         * Memory cleanup
         */
        cleanup() {
            this.performanceData.clear();
            this.throttleMap.clear();
            this.debounceMap.clear();
        }
    };

    // ====================================
    // STORAGE YÖNETİMİ
    // ====================================
    
    const Storage = {
        /**
         * Domain durumu kaydetme
         */
        saveDomainStatus(domain, status, metadata = {}) {
            const normalizedDomain = Utils.normalizeDomain(domain);
            if (!normalizedDomain) return;
            
            const domainData = {
                domain: normalizedDomain,
                status: status, // 'accessible', 'blocked', 'unknown'
                lastChecked: Date.now(),
                checkCount: 1,
                metadata: metadata,
                version: '2.0'
            };
            
            const existingData = this.getDomainStatus(normalizedDomain);
            if (existingData) {
                domainData.checkCount = existingData.checkCount + 1;
                domainData.firstChecked = existingData.firstChecked || existingData.lastChecked;
            } else {
                domainData.firstChecked = Date.now();
            }
            
            try {
                GM_setValue(`domain:${normalizedDomain}`, JSON.stringify(domainData));
                Utils.log('INFO', `Domain durumu kaydedildi: ${normalizedDomain} -> ${status}`);
            } catch (e) {
                Utils.log('ERROR', 'Domain durumu kaydetme hatası:', e);
            }
        },
        
        /**
         * Domain durumu getirme
         */
        getDomainStatus(domain) {
            const normalizedDomain = Utils.normalizeDomain(domain);
            if (!normalizedDomain) return null;
            
            try {
                const storedData = GM_getValue(`domain:${normalizedDomain}`, null);
                if (storedData) {
                    return Utils.safeJsonParse(storedData);
                }
            } catch (e) {
                Utils.log('ERROR', 'Domain durumu okuma hatası:', e);
            }
            
            return null;
        },
        
        /**
         * Tüm domainleri getirme
         */
        getAllDomains() {
            const domains = [];
            
            try {
                const allKeys = GM_listValues();
                
                for (const key of allKeys) {
                    if (key.startsWith('domain:')) {
                        const domainData = Utils.safeJsonParse(GM_getValue(key));
                        if (domainData) {
                            domains.push(domainData);
                        }
                    }
                }
            } catch (e) {
                Utils.log('ERROR', 'Tüm domainleri okuma hatası:', e);
            }
            
            return domains.sort((a, b) => b.lastChecked - a.lastChecked);
        },
        
        /**
         * Domain silme
         */
        deleteDomain(domain) {
            const normalizedDomain = Utils.normalizeDomain(domain);
            if (!normalizedDomain) return;
            
            try {
                GM_deleteValue(`domain:${normalizedDomain}`);
                Utils.log('INFO', `Domain silindi: ${normalizedDomain}`);
            } catch (e) {
                Utils.log('ERROR', 'Domain silme hatası:', e);
            }
        },
        
        /**
         * Eski kayıtları temizleme
         */
        cleanupOldRecords(maxAge = 30 * 24 * 60 * 60 * 1000) {
            const now = Date.now();
            const domains = this.getAllDomains();
            let cleanedCount = 0;
            
            for (const domain of domains) {
                if (now - domain.lastChecked > maxAge) {
                    this.deleteDomain(domain.domain);
                    cleanedCount++;
                }
            }
            
            Utils.log('INFO', `Eski kayıtlar temizlendi: ${cleanedCount} adet`);
        },
        
        /**
         * Varsayılan domainleri ekleme
         */
        initializeDefaultDomains() {
            let addedCount = 0;
            
            for (const domain of CONFIG.DEFAULT_BLOCKED_DOMAINS) {
                if (!this.getDomainStatus(domain)) {
                    this.saveDomainStatus(domain, 'blocked', { source: 'default' });
                    addedCount++;
                }
            }
            
            Utils.log('INFO', `Varsayılan domainler eklendi: ${addedCount} adet`);
        },
        
        /**
         * İstatistikler
         */
        getStats() {
            const domains = this.getAllDomains();
            
            return {
                total: domains.length,
                blocked: domains.filter(d => d.status === 'blocked').length,
                accessible: domains.filter(d => d.status === 'accessible').length,
                unknown: domains.filter(d => d.status === 'unknown').length,
                recentlyChecked: domains.filter(d => Date.now() - d.lastChecked < 24 * 60 * 60 * 1000).length
            };
        }
    };

    // ====================================
    // ERİŞİLEBİLİRLİK KONTROLÜ
    // ====================================
    
    const AccessibilityChecker = {
        // Aktif kontroller
        activeChecks: new Map(),
        
        /**
         * Domain erişilebilirliği kontrol etme
         */
        async checkDomainAccessibility(domain, retryCount = 0) {
            const normalizedDomain = Utils.normalizeDomain(domain);
            if (!normalizedDomain) return false;
            
            // Aynı anda birden fazla kontrol engelleme
            if (this.activeChecks.has(normalizedDomain)) {
                return this.activeChecks.get(normalizedDomain);
            }
            
            const checkPromise = this._performAccessibilityCheck(normalizedDomain, retryCount);
            this.activeChecks.set(normalizedDomain, checkPromise);
            
            try {
                const result = await checkPromise;
                return result;
            } finally {
                this.activeChecks.delete(normalizedDomain);
            }
        },
        
        /**
         * Gerçek erişilebilirlik kontrolü
         */
        async _performAccessibilityCheck(domain, retryCount) {
            const url = `https://${domain}`;
            Utils.log('INFO', `Erişilebilirlik kontrolü: ${domain} (deneme: ${retryCount + 1})`);
            
            return new Promise((resolve) => {
                const startTime = Date.now();
                
                GM_xmlhttpRequest({
                    method: 'GET',
                    url: url,
                    timeout: CONFIG.REQUEST_TIMEOUT,
                    headers: {
                        'User-Agent': navigator.userAgent,
                        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                        'Accept-Language': 'tr-TR,tr;q=0.9,en;q=0.8',
                        'Cache-Control': 'no-cache'
                    },
                    
                    onload: (response) => {
                        const duration = Date.now() - startTime;
                        const isAccessible = this._analyzeResponse(response, domain);
                        
                        Utils.log('INFO', `Kontrol tamamlandı: ${domain} -> ${isAccessible ? 'ERİŞİLEBİLİR' : 'ENGELLİ'} (${duration}ms)`);
                        
                        Storage.saveDomainStatus(domain, isAccessible ? 'accessible' : 'blocked', {
                            responseTime: duration,
                            statusCode: response.status,
                            lastCheck: Date.now()
                        });
                        
                        resolve(isAccessible);
                    },
                    
                    onerror: (error) => {
                        Utils.log('WARN', `Erişim hatası: ${domain}`, error);
                        this._handleCheckError(domain, retryCount, resolve);
                    },
                    
                    ontimeout: () => {
                        Utils.log('WARN', `Zaman aşımı: ${domain}`);
                        this._handleCheckError(domain, retryCount, resolve);
                    }
                });
            });
        },
        
        /**
         * Response analiz etme
         */
        _analyzeResponse(response, domain) {
            // Status code kontrolü
            if (response.status < 200 || response.status >= 400) {
                return false;
            }
            
            // İçerik kontrolü
            const content = response.responseText || '';
            const contentLower = content.toLowerCase();
            
            // Engel belirteçleri kontrolü
            for (const indicator of CONFIG.BLOCKED_INDICATORS) {
                if (contentLower.includes(indicator.toLowerCase())) {
                    Utils.log('DEBUG', `Engel belirteci bulundu: ${domain} -> ${indicator}`);
                    return false;
                }
            }
            
            // Başarılı sayfa belirteçleri
            const successIndicators = ['<!doctype', '<html', '<head', '<body'];
            const hasSuccessIndicator = successIndicators.some(indicator => 
                contentLower.includes(indicator)
            );
            
            if (!hasSuccessIndicator && content.length < 100) {
                return false;
            }
            
            return true;
        },
        
        /**
         * Kontrol hatası yönetimi
         */
        async _handleCheckError(domain, retryCount, resolve) {
            if (retryCount < CONFIG.MAX_RETRY_ATTEMPTS) {
                Utils.log('INFO', `Yeniden deneniyor: ${domain} (${retryCount + 1}/${CONFIG.MAX_RETRY_ATTEMPTS})`);
                
                await Utils.sleep(CONFIG.RETRY_DELAY * (retryCount + 1));
                
                try {
                    const result = await this._performAccessibilityCheck(domain, retryCount + 1);
                    resolve(result);
                } catch (e) {
                    resolve(false);
                }
            } else {
                Utils.log('WARN', `Maksimum deneme sayısı aşıldı: ${domain}`);
                
                Storage.saveDomainStatus(domain, 'blocked', {
                    error: 'connection_failed',
                    lastCheck: Date.now()
                });
                
                resolve(false);
            }
        },
        
        /**
         * Periyodik kontrol başlatma
         */
        startPeriodicCheck() {
            if (!CONFIG.AUTO_CHECK_AVAILABILITY) return;
            
            const checkInterval = setInterval(() => {
                const domains = Storage.getAllDomains();
                const now = Date.now();
                
                for (const domain of domains) {
                    if (now - domain.lastChecked > CONFIG.AVAILABILITY_CHECK_INTERVAL) {
                        this.checkDomainAccessibility(domain.domain);
                    }
                }
            }, CONFIG.DNS_CHECK_INTERVAL);
            
            Utils.log('INFO', 'Periyodik erişilebilirlik kontrolü başlatıldı');
            return checkInterval;
        }
    };

    // ====================================
    // PROXY YÖNETİMİ
    // ====================================
    
    const ProxyManager = {
        // Proxy durumu
        isProxyPage: false,
        currentProxyUrl: null,
        
        /**
         * Başlangıç kontrolleri
         */
        initialize() {
            this.isProxyPage = this._detectProxyPage();
            if (this.isProxyPage) {
                this.currentProxyUrl = this._getCurrentProxyUrl();
                Utils.log('INFO', `Proxy sayfasında: ${this.currentProxyUrl}`);
            }
        },
        
        /**
         * Proxy sayfası tespiti
         */
        _detectProxyPage() {
    const url = window.location.href;
    return CONFIG.PROXY_URLS.some(proxyUrl => {
        const proxyHost = new URL(proxyUrl).hostname;
        return window.location.hostname === proxyHost
            || url.includes('/https%3A%2F%2F');
    });
},        
        /**
         * Mevcut proxy URL'ini alma
         */
        _getCurrentProxyUrl() {
            return CONFIG.PROXY_URLS.find(proxyUrl => {
                try {
                    const proxyHost = new URL(proxyUrl).hostname;
                    return window.location.hostname === proxyHost;
                } catch (e) {
                    return false;
                }
            });
        },
        
        /**
         * Domain proxy gereksinimi kontrolü (devam)
         */
        shouldProxyDomain(domain) {
            const normalizedDomain = Utils.normalizeDomain(domain);
            if (!normalizedDomain) return false;
            
            // Zaten proxy sayfasındaysa proxy yapma
            if (this.isProxyPage) return false;
            
            // Storage'dan domain durumunu kontrol et
            const domainStatus = Storage.getDomainStatus(normalizedDomain);
            
            if (domainStatus) {
                // Son kontrol çok eskiyse yeniden kontrol et
                const now = Date.now();
                if (now - domainStatus.lastChecked > CONFIG.AVAILABILITY_CHECK_INTERVAL) {
                    // Asenkron kontrol başlat
                    AccessibilityChecker.checkDomainAccessibility(normalizedDomain)
                        .then(isAccessible => {
                            if (!isAccessible) {
                                this._autoRedirectToProxy(normalizedDomain);
                            }
                        });
                }
                
                return domainStatus.status === 'blocked';
            }
            
            // Varsayılan engellenen domainlerde mi?
            const isInDefaultBlocked = CONFIG.DEFAULT_BLOCKED_DOMAINS.some(blockedDomain => 
                Utils.domainMatches(normalizedDomain, blockedDomain)
            );
            
            if (isInDefaultBlocked) {
                Storage.saveDomainStatus(normalizedDomain, 'blocked', { source: 'default' });
                return true;
            }
            
            return false;
        },
        
        /**
         * Otomatik proxy yönlendirme
         */
        _autoRedirectToProxy(domain) {
            if (this.isProxyPage) return;
            
            const currentUrl = window.location.href;
            const proxyUrl = Utils.createProxyUrl(currentUrl, Utils.selectRandomProxy());
            
            Utils.log('INFO', `Otomatik proxy yönlendirme: ${domain} -> ${proxyUrl}`);
            
            // Notification göster
            if (CONFIG.UI_ENABLED) {
                GM_notification({
                    text: `${domain} engellendi. Proxy üzerinden yönlendiriliyor...`,
                    title: 'Smart Proxy System',
                    timeout: 3000
                });
            }
            
            window.location.href = proxyUrl;
        },
        
        /**
         * URL'leri proxy ile değiştirme
         */
        processUrls(urls) {
            if (!Array.isArray(urls)) return urls;
            
            return urls.map(url => {
                if (!url || typeof url !== 'string') return url;
                
                try {
                    const urlObj = new URL(url);
                    const domain = urlObj.hostname;
                    
                    if (this.shouldProxyDomain(domain)) {
                        const proxyUrl = Utils.createProxyUrl(url, Utils.selectRandomProxy());
                        Utils.log('DEBUG', `URL proxy ile değiştirildi: ${url} -> ${proxyUrl}`);
                        return proxyUrl;
                    }
                    
                    return url;
                } catch (e) {
                    Utils.log('WARN', 'URL işleme hatası:', e);
                    return url;
                }
            });
        },
        
        /**
         * Tek URL işleme
         */
        processUrl(url) {
            const result = this.processUrls([url]);
            return result[0] || url;
        }
    };

    // ====================================
    // DOM YÖNETİMİ
    // ====================================
    
    const DomManager = {
        // Observer'lar
        observers: [],
        processedElements: new WeakSet(),
        
        /**
         * DOM izleme başlatma
         */
        startObserving() {
            // Mevcut elemanları işle
            this.processExistingElements();
            
            // Yeni elemanları izle
            this.observeNewElements();
            
            Utils.log('INFO', 'DOM izleme başlatıldı');
        },
        
        /**
         * Mevcut elemanları işleme
         */
        processExistingElements() {
            Utils.startPerformance('processExistingElements');
            
            const elements = document.querySelectorAll('a[href], img[src], video[src], source[src], iframe[src], link[href], script[src]');
            
            for (const element of elements) {
                this.processElement(element);
            }
            
            Utils.endPerformance('processExistingElements');
        },
        
        /**
         * Yeni elemanları izleme
         */
        observeNewElements() {
    const observer = new MutationObserver((mutations) => {
        Utils.throttle(() => {
            this.processMutations(mutations);
        }, CONFIG.CONTENT_UPDATE_THROTTLE, 'domMutations');
    });

    observer.observe(document, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['href', 'src', 'action', 'data-src', 'data-url']
    });

    this.observers.push(observer);
},
        
        /**
         * Mutation işleme
         */
        processMutations(mutations) {
            for (const mutation of mutations) {
                if (mutation.type === 'childList') {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            this.processElementAndChildren(node);
                        }
                    }
                } else if (mutation.type === 'attributes') {
                    this.processElement(mutation.target);
                }
            }
        },
        
        /**
         * Element ve çocuklarını işleme
         */
        processElementAndChildren(element) {
            // Ana elementi işle
            this.processElement(element);
            
            // Çocuk elemanları işle
            const childElements = element.querySelectorAll('a[href], img[src], video[src], source[src], iframe[src], link[href], script[src]');
            for (const child of childElements) {
                this.processElement(child);
            }
        },
        
        /**
         * Tek element işleme
         */
        processElement(element) {
    if (!element || this.processedElements.has(element)) return;

    try {
        const tagName = element.tagName.toLowerCase();
        let urlAttribute = null;

        if (tagName === 'a' || tagName === 'link') {
            urlAttribute = 'href';
        } else if (['img', 'video', 'source', 'iframe', 'script'].includes(tagName)) {
            urlAttribute = 'src';
        }

        if (urlAttribute) {
            const originalUrl = element.getAttribute(urlAttribute);
            if (originalUrl) {
                const processedUrl = ProxyManager.processUrl(originalUrl);
                if (processedUrl !== originalUrl) {
                    element.setAttribute(urlAttribute, processedUrl);
                    Utils.log('DEBUG', `Element URL güncellendi: ${tagName} -> ${processedUrl}`);
                }
            }
        }

        // CSS içeriği işleme
        if (tagName === 'style') {
            const cssContent = element.textContent;
            const processedCss = this.processCssContent(cssContent);
            if (processedCss !== cssContent) {
                element.textContent = processedCss;
                Utils.log('DEBUG', `CSS içeriği güncellendi: ${tagName}`);
            }
        }

        this.processedElements.add(element);
    } catch (e) {
        Utils.log('WARN', 'Element işleme hatası:', e);
    }
},

processCssContent(css) {
    if (!css) return css;
    const urlRegex = /url`\(['"]?([^'")]+)['"]?\)`/g;
    return css.replace(urlRegex, (match, url) => {
        const processedUrl = ProxyManager.processUrl(url);
        return `url('${processedUrl}')`;
    });
},
        
        /**
         * Temizlik
         */
        cleanup() {
            for (const observer of this.observers) {
                observer.disconnect();
            }
            this.observers.length = 0;
            this.processedElements = new WeakSet();
        }
    };

    // ====================================
    // NETWORK İNTERCEPTION
    // ====================================
    
    const NetworkInterceptor = {
        // Orijinal fonksiyonlar
        originalFetch: null,
        originalXHR: null,
        
        /**
         * Network interception başlatma
         */
        initialize() {
            this.interceptFetch();
            this.interceptXHR();
            Utils.log('INFO', 'Network interception başlatıldı');
        },
        
        /**
         * Fetch API interception
         */
        interceptFetch() {
            if (typeof window.fetch !== 'function') return;
            
            this.originalFetch = window.fetch;
            
            window.fetch = async (input, init = {}) => {
                try {
                    const url = typeof input === 'string' ? input : input.url;
                    const processedUrl = ProxyManager.processUrl(url);
                    
                    if (processedUrl !== url) {
                        Utils.log('DEBUG', `Fetch URL proxy ile değiştirildi: ${url} -> ${processedUrl}`);
                        
                        if (typeof input === 'string') {
                            input = processedUrl;
                        } else {
                            input = new Request(processedUrl, input);
                        }
                    }
                    
                    return await this.originalFetch(input, init);
                } catch (e) {
                    Utils.log('ERROR', 'Fetch interception hatası:', e);
                    return await this.originalFetch(input, init);
                }
            };
        },
        
        /**
         * XMLHttpRequest interception
         */
        interceptXHR() {
            if (typeof window.XMLHttpRequest !== 'function') return;
            
            this.originalXHR = window.XMLHttpRequest;
            
            window.XMLHttpRequest = function() {
                const xhr = new NetworkInterceptor.originalXHR();
                const originalOpen = xhr.open;
                
                xhr.open = function(method, url, ...args) {
                    try {
                        const processedUrl = ProxyManager.processUrl(url);
                        if (processedUrl !== url) {
                            Utils.log('DEBUG', `XHR URL proxy ile değiştirildi: ${url} -> ${processedUrl}`);
                            url = processedUrl;
                        }
                    } catch (e) {
                        Utils.log('ERROR', 'XHR interception hatası:', e);
                    }
                    
                    return originalOpen.call(this, method, url, ...args);
                };
                
                return xhr;
            };
        },
        
        /**
         * Temizlik
         */
        cleanup() {
            if (this.originalFetch) {
                window.fetch = this.originalFetch;
            }
            if (this.originalXHR) {
                window.XMLHttpRequest = this.originalXHR;
            }
        }
    };

    // ====================================
    // KULLANICI ARAYÜZÜ
    // ====================================
    
    const UI = {
        // UI elemanları
        panel: null,
        isVisible: false,
        
        /**
         * UI başlatma
         */
        initialize() {
            if (!CONFIG.UI_ENABLED) return;
            
            this.createPanel();
            this.attachEventListeners();
            this.updateStats();
            
            Utils.log('INFO', 'UI başlatıldı');
        },
        
        /**
         * Panel oluşturma
         */
        createPanel() {
            this.panel = document.createElement('div');
            this.panel.id = 'smart-proxy-panel';
            this.panel.innerHTML = this.getPanelHTML();
            
            // Stil ekleme
            this.addStyles();
            
            // Pozisyon ayarlama
            this.setPosition();
            
            document.body.appendChild(this.panel);
        },
        
        /**
         * Panel HTML'i
         */
        getPanelHTML() {
            return `
                <div class="sp-header">
                    <div class="sp-title">
                        <span class="sp-icon">🔒</span>
                        Smart Proxy System
                    </div>
                    <div class="sp-controls">
                        <button class="sp-btn sp-btn-minimize" title="Minimize">−</button>
                        <button class="sp-btn sp-btn-close" title="Close">×</button>
                    </div>
                </div>
                
                <div class="sp-content">
                    <div class="sp-stats">
                        <div class="sp-stat">
                            <span class="sp-label">Toplam Domain:</span>
                            <span class="sp-value" id="sp-total">0</span>
                        </div>
                        <div class="sp-stat">
                            <span class="sp-label">Engellenen:</span>
                            <span class="sp-value sp-blocked" id="sp-blocked">0</span>
                        </div>
                        <div class="sp-stat">
                            <span class="sp-label">Erişilebilir:</span>
                            <span class="sp-value sp-accessible" id="sp-accessible">0</span>
                        </div>
                    </div>
                    
                    <div class="sp-actions">
                        <button class="sp-btn sp-btn-primary" id="sp-check-current">
                            Mevcut Siteyi Kontrol Et
                        </button>
                        <button class="sp-btn sp-btn-secondary" id="sp-add-domain">
                            Domain Ekle
                        </button>
                        <button class="sp-btn sp-btn-secondary" id="sp-view-domains">
                            Domainleri Görüntüle
                        </button>
                    </div>
                    
                    <div class="sp-current-status">
                        <div class="sp-status-item">
                            <span class="sp-label">Mevcut Site:</span>
                            <span class="sp-value" id="sp-current-domain">${window.location.hostname}</span>
                        </div>
                        <div class="sp-status-item">
                            <span class="sp-label">Durum:</span>
                            <span class="sp-value" id="sp-current-status">Kontrol ediliyor...</span>
                        </div>
                    </div>
                </div>
            `;
        },
        
        /**
         * Stil ekleme
         */
        addStyles() {
            const style = document.createElement('style');
            style.textContent = `
                #smart-proxy-panel {
                    position: fixed;
                    width: 300px;
                    min-height: 200px;
                    background: #fff;
                    border: 1px solid #ddd;
                    border-radius: 8px;
                    box-shadow: 0 4px 12px rgba(0,0,0,0.15);
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    font-size: 14px;
                    z-index: 999999;
                    transition: all 0.3s ease;
                }
                
                .sp-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    padding: 12px 16px;
                    background: #f8f9fa;
                    border-bottom: 1px solid #e9ecef;
                    border-radius: 8px 8px 0 0;
                    cursor: move;
                }
                
                .sp-title {
                    display: flex;
                    align-items: center;
                    font-weight: 600;
                    color: #333;
                }
                
                .sp-icon {
                    margin-right: 8px;
                }
                
                .sp-controls {
                    display: flex;
                    gap: 4px;
                }
                
                .sp-btn {
                    padding: 4px 8px;
                    border: 1px solid #ddd;
                    border-radius: 4px;
                    background: #fff;
                    cursor: pointer;
                    font-size: 12px;
                    transition: all 0.2s ease;
                }
                
                .sp-btn:hover {
                    background: #f8f9fa;
                }
                
                .sp-btn-primary {
                    background: #007bff;
                    color: white;
                    border-color: #007bff;
                }
                
                .sp-btn-primary:hover {
                    background: #0056b3;
                }
                
                .sp-btn-secondary {
                    background: #6c757d;
                    color: white;
                    border-color: #6c757d;
                }
                
                .sp-btn-secondary:hover {
                    background: #545b62;
                }
                
                .sp-content {
                    padding: 16px;
                }
                
                .sp-stats {
                    display: flex;
                    flex-direction: column;
                    gap: 8px;
                    margin-bottom: 16px;
                }
                
                .sp-stat {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .sp-label {
                    color: #666;
                    font-size: 13px;
                }
                
                .sp-value {
                    font-weight: 600;
                    color: #333;
                }
                
                .sp-blocked {
                    color: #dc3545;
                }
                
                .sp-accessible {
                    color: #28a745;
                }
                
                .sp-actions {
                    display: flex;
                    flex-direction: column;
                    gap: 8px;
                    margin-bottom: 16px;
                }
                
                .sp-current-status {
                    border-top: 1px solid #e9ecef;
                    padding-top: 12px;
                    font-size: 13px;
                }
                
                .sp-status-item {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 4px;
                }
                
                .sp-minimized .sp-content {
                    display: none;
                }
                
                .sp-minimized {
                    height: auto;
                    min-height: auto;
                }
                
                @media (prefers-color-scheme: dark) {
                    #smart-proxy-panel {
                        background: #2d3748;
                        border-color: #4a5568;
                        color: #e2e8f0;
                    }
                    
                    .sp-header {
                        background: #1a202c;
                        border-color: #4a5568;
                    }
                    
                    .sp-title {
                        color: #e2e8f0;
                    }
                    
                    .sp-btn {
                        background: #4a5568;
                        border-color: #4a5568;
                        color: #e2e8f0;
                    }
                    
                    .sp-btn:hover {
                        background: #2d3748;
                    }
                    
                    .sp-value {
                        color: #e2e8f0;
                    }
                    
                    .sp-label {
                        color: #a0aec0;
                    }
                }
            `;
            
            document.head.appendChild(style);
        },
        
        /**
         * Pozisyon ayarlama
         */
        setPosition() {
            const position = CONFIG.UI_POSITION.split('-');
            const vertical = position[0]; // 'top' or 'bottom'
            const horizontal = position[1]; // 'left' or 'right'
            
            this.panel.style[vertical] = '20px';
            this.panel.style[horizontal] = '20px';
        },
        
        /**
         * Event listener'lar
         */
        attachEventListeners() {
            // Panel sürükleme
            this.makeDraggable();
            
            // Minimize/Close
            this.panel.querySelector('.sp-btn-minimize').addEventListener('click', () => {
                this.toggleMinimize();
            });
            
            this.panel.querySelector('.sp-btn-close').addEventListener('click', () => {
                this.hide();
            });
            
            // Buton event'leri
            this.panel.querySelector('#sp-check-current').addEventListener('click', () => {
                this.checkCurrentDomain();
            });
            
            this.panel.querySelector('#sp-add-domain').addEventListener('click', () => {
                this.showAddDomainDialog();
            });
            
            this.panel.querySelector('#sp-view-domains').addEventListener('click', () => {
                this.showDomainsDialog();
            });
            
            // Klavye kısayolları
            document.addEventListener('keydown', (e) => {
                if (e.ctrlKey && e.shiftKey && e.key === 'P') {
                    this.toggle();
                }
            });
        },
        
        /**
         * Panel sürüklenebilir yapma
         */
        makeDraggable() {
            const header = this.panel.querySelector('.sp-header');
            let isDragging = false;
            let startX, startY, startLeft, startTop;
            
            header.addEventListener('mousedown', (e) => {
                isDragging = true;
                startX = e.clientX;
                startY = e.clientY;
                startLeft = parseInt(this.panel.style.left || 0);
                startTop = parseInt(this.panel.style.top || 0);
            });
            
            document.addEventListener('mousemove', (e) => {
                if (!isDragging) return;
                
                const deltaX = e.clientX - startX;
                const deltaY = e.clientY - startY;
                
                this.panel.style.left = (startLeft + deltaX) + 'px';
                this.panel.style.top = (startTop + deltaY) + 'px';
                this.panel.style.right = 'auto';
                this.panel.style.bottom = 'auto';
            });
            
            document.addEventListener('mouseup', () => {
                isDragging = false;
            });
        },
        
        /**
         * İstatistikleri güncelleme
         */
        updateStats() {
            const stats = Storage.getStats();
            
            this.panel.querySelector('#sp-total').textContent = stats.total;
            this.panel.querySelector('#sp-blocked').textContent = stats.blocked;
            this.panel.querySelector('#sp-accessible').textContent = stats.accessible;
            
            // Mevcut domain durumu
            this.updateCurrentDomainStatus();
        },
        
        /**
         * Mevcut domain durumu güncelleme
         */
        async updateCurrentDomainStatus() {
            const domain = window.location.hostname;
            const statusElement = this.panel.querySelector('#sp-current-status');
            
            statusElement.textContent = 'Kontrol ediliyor...';
            
            try {
                const isAccessible = await AccessibilityChecker.checkDomainAccessibility(domain);
                statusElement.textContent = isAccessible ? 'Erişilebilir' : 'Engellenen';
                statusElement.className = `sp-value ${isAccessible ? 'sp-accessible' : 'sp-blocked'}`;
            } catch (e) {
                statusElement.textContent = 'Bilinmiyor';
                statusElement.className = 'sp-value';
            }
        },
        
        /**
         * Mevcut domain kontrolü
         */
        async checkCurrentDomain() {
            const domain = window.location.hostname;
            const button = this.panel.querySelector('#sp-check-current');
            
            button.disabled = true;
            button.textContent = 'Kontrol ediliyor...';
            
            try {
                const isAccessible = await AccessibilityChecker.checkDomainAccessibility(domain);
                
                GM_notification({
                    text: `${domain} ${isAccessible ? 'erişilebilir' : 'engellenen'} durumda`,
                    title: 'Smart Proxy System',
                    timeout: 3000
                });
                
                this.updateStats();
            } catch (e) {
                GM_notification({
                    text: 'Kontrol sırasında hata oluştu',
                    title: 'Smart Proxy System',
                    timeout: 3000
                });
            } finally {
                button.disabled = false;
                button.textContent = 'Mevcut Siteyi Kontrol Et';
            }
        },
        
        /**
         * Domain ekleme dialogu
         */
        showAddDomainDialog() {
            const domain = prompt('Eklemek istediğiniz domain adını girin:');
            if (domain) {
                const normalizedDomain = Utils.normalizeDomain(domain);
                if (normalizedDomain) {
                    Storage.saveDomainStatus(normalizedDomain, 'blocked', { source: 'manual' });
                    this.updateStats();
                    
                    GM_notification({
                        text: `${normalizedDomain} engellenen domainlere eklendi`,
                        title: 'Smart Proxy System',
                        timeout: 3000
                    });
                } else {
                    alert('Geçersiz domain formatı');
                }
            }
        },
        
        /**
         * Domainleri görüntüleme dialogu
         */
        showDomainsDialog() {
            const domains = Storage.getAllDomains();
            const domainList = domains.map(domain => 
                `${domain.domain} - ${domain.status} (${new Date(domain.lastChecked).toLocaleDateString()})`
            ).join('\n');
            
            alert(`Kayıtlı Domainler:\n\n${domainList || 'Kayıtlı domain bulunamadı'}`);
        },
        
        /**
         * Panel göster/gizle
         */
        toggle() {
            this.isVisible ? this.hide() : this.show();
        },
        
        show() {
            this.panel.style.display = 'block';
            this.isVisible = true;
        },
        
        hide() {
            this.panel.style.display = 'none';
            this.isVisible = false;
        },
        
        /**
         * Minimize/Maximize
         */
        toggleMinimize() {
            this.panel.classList.toggle('sp-minimized');
        },
        
        /**
         * Temizlik
         */
        cleanup() {
            if (this.panel) {
                this.panel.remove();
                this.panel = null;
            }
        }
    };

    // ====================================
    // ANA UYGULAMA
    // ====================================
    
    const SmartProxySystem = {
        // Sistem durumu
        isInitialized: false,
        intervals: [],
        
        /**
         * Sistem başlatma
         */
        async initialize() {
            if (this.isInitialized) return;
            
            Utils.log('INFO', 'Smart Proxy System başlatılıyor...');
            Utils.startPerformance('systemInit');
            
            try {
                // Konfigürasyon doğrulama
                this.validateConfig();
                
                // Storage başlatma
                Storage.initializeDefaultDomains();
                
                // Proxy manager başlatma
                ProxyManager.initialize();
                
                // Erişilebilirlik kontrolleri
                const periodicCheck = AccessibilityChecker.startPeriodicCheck();
                if (periodicCheck) {
                    this.intervals.push(periodicCheck);
                }
                
                // Network interception
                NetworkInterceptor.initialize();
                
                // DOM yönetimi
                if (document.readyState === 'loading') {
                    document.addEventListener('DOMContentLoaded', () => {
                        DomManager.startObserving();
                    });
                } else {
                    DomManager.startObserving();
                }
                
                // UI başlatma
                if (CONFIG.UI_ENABLED) {
                    if (document.readyState === 'loading') {
                        document.addEventListener('DOMContentLoaded', () => {
                            UI.initialize();
                        });
                    } else {
                        UI.initialize();
                    }
                }
                
                // Mevcut sayfa kontrol
                this.checkCurrentPage();
                
                // Temizlik scheduler
                this.scheduleCleanup();
                
                this.isInitialized = true;
                Utils.endPerformance('systemInit');
                Utils.log('INFO', 'Smart Proxy System başarıyla başlatıldı');
                
            } catch (error) {
                Utils.log('ERROR', 'Sistem başlatma hatası:', error);
                this.handleInitializationError(error);
            }
        },
        
        /**
         * Konfigürasyon doğrulama
         */
        validateConfig() {
            if (!CONFIG.PROXY_URLS || CONFIG.PROXY_URLS.length === 0) {
                throw new Error('Proxy URL\'leri tanımlanmamış');
            }
            
            for (const url of CONFIG.PROXY_URLS) {
                try {
                    new URL(url);
                } catch (e) {
                    throw new Error(`Geçersiz proxy URL: ${url}`);
                }
            }
        },
        
        /**
         * Mevcut sayfa kontrolü
         */
        async checkCurrentPage() {
            const domain = window.location.hostname;
            
            // Mevcut domain proxy gerektiriyor mu?
            if (ProxyManager.shouldProxyDomain(domain)) {
                Utils.log('INFO', `Mevcut domain engellenen listesinde: ${domain}`);
                
                if (!ProxyManager.isProxyPage) {
                    // Erişilebilirlik kontrolü yap
                    const isAccessible = await AccessibilityChecker.checkDomainAccessibility(domain);
                    
                    if (!isAccessible) {
                        Utils.log('INFO', `Domain erişilemez durumda, proxy'ye yönlendiriliyor: ${domain}`);
                        ProxyManager._autoRedirectToProxy(domain);
                    }
                }
            }
        },
        
        /**
         * Temizlik scheduler
         */
        scheduleCleanup() {
            // Günlük temizlik
            const cleanupInterval = setInterval(() => {
                Storage.cleanupOldRecords();
                Utils.cleanup();
            }, 24 * 60 * 60 * 1000); // 24 saat
            
            this.intervals.push(cleanupInterval);
        },
        
        /**
         * Başlatma hatası yönetimi
         */
                handleInitializationError(error) {
            console.error('[SmartProxy] Kritik hata:', error);

            // Temel fonksiyonaliteyi koru
            try {
                ProxyManager.initialize();

                // Basit domain kontrolü
                const domain = window.location.hostname;
                if (CONFIG.DEFAULT_BLOCKED_DOMAINS.includes(domain)) {
                    const proxyUrl = Utils.createProxyUrl(window.location.href, CONFIG.PROXY_URLS[0]);
                    window.location.href = proxyUrl;
                }
            } catch (e) {
                console.error('[SmartProxy] Hata devam ediyor:', e);
            }
        }
    };

    // Sistemi başlat
    SmartProxySystem.initialize();
}();
