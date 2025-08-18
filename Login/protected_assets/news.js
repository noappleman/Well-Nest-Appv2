// Newsletter App Main JavaScript
class NewsletterApp {
    constructor() {
        this.currentLanguage = 'en';
        this.currentSource = 'general';
        this.apiKey = '7da335179ec2422090bf09a8f4103b56'; // NewsAPI.org key for international news
        this.baseUrl = 'https://newsapi.org/v2';
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.loadSavedPreferences();
        this.loadNews();
    }

    setupEventListeners() {
        // Language selector
        const languageSelect = document.getElementById('language');
        languageSelect.addEventListener('change', (e) => {
            this.currentLanguage = e.target.value;
            updateLanguage(this.currentLanguage);
            // Reload news content in the new language
            this.loadNews();
        });

        // News source selector
        const newsSourceSelect = document.getElementById('newsSource');
        newsSourceSelect.addEventListener('change', (e) => {
            this.currentSource = e.target.value;
            this.loadNews();
        });

        // Refresh button
        const refreshBtn = document.getElementById('refreshBtn');
        refreshBtn.addEventListener('click', () => {
            this.loadNews();
        });

        // Retry button
        const retryBtn = document.getElementById('retryBtn');
        retryBtn.addEventListener('click', () => {
            this.loadNews();
        });
    }

    loadSavedPreferences() {
        const savedLanguage = localStorage.getItem('preferredLanguage') || 'en';
        const savedSource = localStorage.getItem('preferredNewsSource') || 'general';
        
        this.currentLanguage = savedLanguage;
        this.currentSource = savedSource;
        
        document.getElementById('language').value = savedLanguage;
        document.getElementById('newsSource').value = savedSource;
        
        updateLanguage(savedLanguage);
    }

    async loadNews() {
        this.showLoading();
        this.hideError();

        try {
            let articles;
            
            // Check if it's a Straits Times RSS feed
            if (this.currentSource.startsWith('st-')) {
                articles = await this.fetchStraitsTimes();
            } else {
                // Use real API with the provided key for all other sources
                articles = await this.fetchNewsFromAPI();
            }

            // Display news immediately, then translate in background
            this.displayNews(articles);
            
            // Translate articles in background without blocking UI
            this.translateArticlesInBackground(articles);
            this.savePreferences();
        } catch (error) {
            console.error('Error loading news:', error);
            this.showError();
        } finally {
            this.hideLoading();
        }
    }

    async fetchNewsFromAPI() {
        const language = this.getLanguageCode();
        let url;

        if (this.currentSource === 'general') {
            url = `${this.baseUrl}/top-headlines?country=sg&language=${language}&apiKey=${this.apiKey}`;
        } else {
            url = `${this.baseUrl}/top-headlines?sources=${this.currentSource}&apiKey=${this.apiKey}`;
        }

        console.log('Fetching from URL:', url);
        
        const response = await fetch(url);
        if (!response.ok) {
            console.error('API response not ok:', response.status, response.statusText);
            throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log('API response data:', data);
        
        if (data.status !== 'ok') {
            console.error('API returned error:', data.message);
            throw new Error(`API error: ${data.message}`);
        }
        
        const articles = data.articles || [];
        console.log('Articles count:', articles.length);
        
        // Add translation markers for NewsAPI articles
        return articles.map(article => ({
            ...article,
            originalTitle: article.title,
            originalDescription: article.description,
            needsTranslation: true
        }));
    }

    async fetchStraitsTimes() {
        // Map source to RSS URL
        const rssUrls = {
            'st-singapore': 'https://www.straitstimes.com/news/singapore/rss.xml',
            'st-asia': 'https://www.straitstimes.com/news/asia/rss.xml',
            'st-world': 'https://www.straitstimes.com/news/world/rss.xml',
            'st-business': 'https://www.straitstimes.com/news/business/rss.xml',
            'st-tech': 'https://www.straitstimes.com/news/tech/rss.xml'
        };

        const rssUrl = rssUrls[this.currentSource];
        if (!rssUrl) {
            throw new Error('Invalid Straits Times source');
        }

        try {
            // Use RSS2JSON service to parse RSS feeds (CORS-friendly)
            const proxyUrl = `https://api.rss2json.com/v1/api.json?rss_url=${encodeURIComponent(rssUrl)}&count=10`;
            
            const response = await fetch(proxyUrl);
            if (!response.ok) {
                throw new Error(`RSS fetch failed: ${response.status}`);
            }

            const data = await response.json();
            
            if (data.status !== 'ok') {
                throw new Error('RSS parsing failed');
            }

            // Convert RSS items to article format with optimized image fetching
            const articles = data.items.map((item, index) => {
                // Enhanced image extraction for Straits Times
                let imageUrl = null;
                
                // Try multiple sources for images from RSS first
                if (item.enclosure && item.enclosure.link) {
                    imageUrl = item.enclosure.link;
                } else if (item.thumbnail) {
                    imageUrl = item.thumbnail;
                } else if (item.content) {
                    imageUrl = this.extractImageFromContent(item.content);
                } else if (item.description) {
                    imageUrl = this.extractImageFromContent(item.description);
                }
                
                // Use fallback image if no RSS image found (faster than fetching from web pages)
                if (!imageUrl) {
                    imageUrl = this.getStraitsFallbackImage(this.currentSource, index);
                }
                
                return {
                    title: item.title,
                    description: item.description ? this.stripHtml(item.description) : 'No description available',
                    url: item.link,
                    urlToImage: imageUrl,
                    source: { name: 'The Straits Times' },
                    publishedAt: item.pubDate,
                    originalTitle: item.title,
                    originalDescription: item.description ? this.stripHtml(item.description) : 'No description available',
                    needsTranslation: true, // Mark for translation
                    needsImageFetch: !imageUrl || imageUrl.includes('unsplash') // Mark if needs real image
                };
            });
            
            // Optionally fetch real images for first few articles only (for speed)
            this.fetchRealImagesInBackground(articles.slice(0, 3));
            
            return articles;

        } catch (error) {
            console.warn('RSS fetch failed, using fallback method:', error);
            // Fallback to mock Straits Times data if RSS fails
            return this.getStraitsMockNews();
        }
    }

    stripHtml(html) {
        const tmp = document.createElement('div');
        tmp.innerHTML = html;
        return tmp.textContent || tmp.innerText || '';
    }

    extractImageFromContent(content) {
        if (!content) return null;
        
        // Try multiple image extraction patterns for Straits Times
        const patterns = [
            // Standard img tags
            /<img[^>]+src=["']([^"']+)["']/gi,
            // Img tags without quotes
            /<img[^>]+src=([^\s>]+)/gi,
            // Direct image URLs in content
            /https?:\/\/[^\s"'<>]+\.(jpg|jpeg|png|gif|webp|avif)/gi,
            // Straits Times specific image patterns
            /https?:\/\/[^\s"'<>]*straitstimes[^\s"'<>]*\.(jpg|jpeg|png|gif|webp)/gi,
            // Media URLs
            /https?:\/\/[^\s"'<>]*\/media\/[^\s"'<>]*\.(jpg|jpeg|png|gif|webp)/gi
        ];
        
        for (const pattern of patterns) {
            const matches = content.matchAll(pattern);
            for (const match of matches) {
                const url = match[1] || match[0];
                if (url && url.startsWith('http') && !url.includes('logo') && !url.includes('icon')) {
                    return url;
                }
            }
        }
        
        return null;
    }

    async fetchImageFromArticle(articleUrl) {
        if (!articleUrl) return null;
        
        try {
            // Use a CORS proxy to fetch the article page
            const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(articleUrl)}`;
            
            const response = await fetch(proxyUrl);
            if (!response.ok) {
                throw new Error(`Failed to fetch article: ${response.status}`);
            }
            
            const data = await response.json();
            const htmlContent = data.contents;
            
            if (!htmlContent) {
                throw new Error('No content received');
            }
            
            // Extract images from the article HTML
            const imageUrl = this.extractMainImageFromHTML(htmlContent);
            
            // Add image resizing parameters for Straits Times images
            if (imageUrl && imageUrl.includes('straitstimes.com')) {
                // Add width parameter to resize the image to match our container
                return imageUrl.includes('?') ? 
                    `${imageUrl}&w=400&h=200&fit=crop` : 
                    `${imageUrl}?w=400&h=200&fit=crop`;
            }
            
            return imageUrl;
            
        } catch (error) {
            console.warn('Failed to fetch article content:', error);
            return null;
        }
    }
    
    extractMainImageFromHTML(html) {
        if (!html) return null;
        
        // Try regex patterns first for meta tags (more reliable than DOM parsing)
        const metaPatterns = [
            /<meta[^>]*property=["']og:image["'][^>]*content=["']([^"']+)["']/i,
            /<meta[^>]*content=["']([^"']+)["'][^>]*property=["']og:image["']/i,
            /<meta[^>]*name=["']twitter:image["'][^>]*content=["']([^"']+)["']/i,
            /<meta[^>]*content=["']([^"']+)["'][^>]*name=["']twitter:image["']/i
        ];
        
        for (const pattern of metaPatterns) {
            const match = html.match(pattern);
            if (match && match[1]) {
                let imageUrl = match[1];
                if (imageUrl.startsWith('//')) {
                    imageUrl = 'https:' + imageUrl;
                } else if (imageUrl.startsWith('/')) {
                    imageUrl = 'https://www.straitstimes.com' + imageUrl;
                }
                if (this.isValidImageUrl(imageUrl)) {
                    return imageUrl;
                }
            }
        }
        
        // Try to find images in JSON-LD structured data
        const jsonLdMatch = html.match(/<script[^>]*type=["']application\/ld\+json["'][^>]*>([^<]+)<\/script>/i);
        if (jsonLdMatch) {
            try {
                const jsonData = JSON.parse(jsonLdMatch[1]);
                if (jsonData.image) {
                    const imageUrl = Array.isArray(jsonData.image) ? jsonData.image[0] : jsonData.image;
                    if (typeof imageUrl === 'string' && this.isValidImageUrl(imageUrl)) {
                        return imageUrl;
                    } else if (imageUrl.url && this.isValidImageUrl(imageUrl.url)) {
                        return imageUrl.url;
                    }
                }
            } catch (e) {
                // Ignore JSON parsing errors
            }
        }
        
        // Create a temporary DOM element to parse HTML for additional selectors
        const tempDiv = document.createElement('div');
        tempDiv.innerHTML = html;
        
        // Try to find the main article image using various selectors
        const imageSelectors = [
            'meta[property="og:image"]',
            'meta[name="twitter:image"]',
            'meta[name="twitter:image:src"]',
            '.article-image img',
            '.story-image img',
            '.lead-image img',
            '.hero-image img',
            '.featured-image img',
            'article img',
            '.content img',
            '.story-content img',
            'img[src*="straitstimes"]',
            'img[src*="static.straitstimes"]',
            'img[src*="s3fs-public"]',
            'img[data-src*="straitstimes"]',
            'picture img',
            'figure img'
        ];
        
        for (const selector of imageSelectors) {
            const element = tempDiv.querySelector(selector);
            if (element) {
                let imageUrl = element.getAttribute('content') || 
                              element.getAttribute('src') || 
                              element.getAttribute('data-src') ||
                              element.getAttribute('data-lazy-src');
                              
                if (imageUrl) {
                    // Ensure it's a full URL
                    if (imageUrl.startsWith('//')) {
                        imageUrl = 'https:' + imageUrl;
                    } else if (imageUrl.startsWith('/')) {
                        imageUrl = 'https://www.straitstimes.com' + imageUrl;
                    }
                    
                    if (this.isValidImageUrl(imageUrl)) {
                        return imageUrl;
                    }
                }
            }
        }
        
        // Last resort: find any large image in the content
        const allImages = tempDiv.querySelectorAll('img');
        for (const img of allImages) {
            let imageUrl = img.getAttribute('src') || img.getAttribute('data-src');
            if (imageUrl) {
                if (imageUrl.startsWith('//')) {
                    imageUrl = 'https:' + imageUrl;
                } else if (imageUrl.startsWith('/')) {
                    imageUrl = 'https://www.straitstimes.com' + imageUrl;
                }
                
                // Check if it looks like a main content image (not ads, logos, etc.)
                if (this.isValidImageUrl(imageUrl) && 
                    (imageUrl.includes('straitstimes') || imageUrl.includes('s3fs-public'))) {
                    return imageUrl;
                }
            }
        }
        
        return null;
    }
    
    isValidImageUrl(url) {
        if (!url || typeof url !== 'string') return false;
        
        // Must be a valid image URL
        const imageExtensions = /\.(jpg|jpeg|png|gif|webp|avif)($|\?)/i;
        const hasImageExtension = imageExtensions.test(url);
        
        // Or be from a known image hosting domain
        const isImageDomain = url.includes('straitstimes') || 
                             url.includes('s3fs-public') ||
                             url.includes('/media/') ||
                             url.includes('/images/');
        
        // Filter out unwanted images
        const unwantedTerms = ['logo', 'icon', 'avatar', 'thumbnail', 'favicon', 'sprite', 'button', 'banner', 'ad'];
        const hasUnwantedTerms = unwantedTerms.some(term => url.toLowerCase().includes(term));
        
        return (hasImageExtension || isImageDomain) && !hasUnwantedTerms && url.startsWith('http');
    }

    // Translation function for Straits Times articles
    async translateArticlesIfNeeded(articles) {
        // If language is English, return articles as-is
        if (this.currentLanguage === 'en') {
            return articles;
        }

        // Create translated versions of articles
        const translatedArticles = await Promise.all(
            articles.map(async (article) => {
                if (article.needsTranslation) {
                    try {
                        const translatedTitle = await this.translateText(article.originalTitle, this.currentLanguage);
                        const translatedDescription = await this.translateText(article.originalDescription, this.currentLanguage);
                        
                        return {
                            ...article,
                            title: translatedTitle || article.originalTitle,
                            description: translatedDescription || article.originalDescription
                        };
                    } catch (error) {
                        console.warn('Translation failed for article:', error);
                        return article; // Return original if translation fails
                    }
                }
                return article;
            })
        );

        return translatedArticles;
    }

    // Background translation that updates UI without blocking initial load
    async translateArticlesInBackground(articles) {
        // Only translate if not English
        if (this.currentLanguage === 'en') {
            return;
        }

        // Translate articles one by one and update the UI as they complete
        articles.forEach(async (article, index) => {
            if (article.needsTranslation) {
                try {
                    const translatedTitle = await this.translateText(article.originalTitle, this.currentLanguage);
                    const translatedDescription = await this.translateText(article.originalDescription, this.currentLanguage);
                    
                    // Update the specific article card in the UI
                    this.updateArticleCard(index, {
                        title: translatedTitle || article.originalTitle,
                        description: translatedDescription || article.originalDescription
                    });
                } catch (error) {
                    console.warn('Background translation failed for article:', error);
                }
            }
        });
    }

    // Update a specific article card in the UI
    updateArticleCard(index, updates) {
        const newsCards = document.querySelectorAll('.news-card');
        if (newsCards[index]) {
            const card = newsCards[index];
            
            if (updates.title) {
                const titleElement = card.querySelector('.news-title');
                if (titleElement) {
                    // Preserve layout by maintaining max height
                    const currentHeight = titleElement.offsetHeight;
                    titleElement.textContent = updates.title;
                    // Ensure we don't expand beyond original dimensions
                    titleElement.style.maxHeight = `${currentHeight}px`;
                    titleElement.style.overflow = 'hidden';
                }
            }
            
            if (updates.description) {
                const descElement = card.querySelector('.news-description');
                if (descElement) {
                    // Preserve layout by maintaining max height
                    const currentHeight = descElement.offsetHeight;
                    descElement.textContent = updates.description;
                    // Ensure we don't expand beyond original dimensions
                    descElement.style.maxHeight = `${currentHeight}px`;
                    descElement.style.overflow = 'hidden';
                }
            }
        }
    }

    // Reliable translation using Google Translate web interface
    async translateText(text, targetLanguage) {
        if (!text || text.length > 1000) {
            return text; // Skip very long texts
        }

        // Try multiple translation approaches
        const translationMethods = [
            // Method 1: Google Translate via web scraping (most reliable)
            async () => {
                try {
                    const targetLang = this.getGoogleTranslateLanguageCode(targetLanguage);
                    const encodedText = encodeURIComponent(text);
                    
                    // Use Google Translate's web interface via a CORS proxy
                    const proxyUrl = `https://api.allorigins.win/get?url=${encodeURIComponent(`https://translate.googleapis.com/translate_a/single?client=gtx&sl=en&tl=${targetLang}&dt=t&q=${encodedText}`)}`;
                    
                    const response = await fetch(proxyUrl);
                    if (response.ok) {
                        const data = await response.json();
                        const result = JSON.parse(data.contents);
                        
                        if (result && result[0] && result[0][0] && result[0][0][0]) {
                            return result[0][0][0];
                        }
                    }
                    throw new Error('Google Translate failed');
                } catch (error) {
                    throw new Error(`Google Translate error: ${error.message}`);
                }
            },
            
            // Method 2: Microsoft Translator (backup)
            async () => {
                try {
                    const targetLang = this.getMicrosoftLanguageCode(targetLanguage);
                    const response = await fetch(`https://api.mymemory.translated.net/get?q=${encodeURIComponent(text)}&langpair=en|${targetLang}`);
                    
                    if (response.ok) {
                        const data = await response.json();
                        if (data.responseStatus === 200 && data.responseData && !data.responseData.translatedText.includes('MYMEMORY WARNING')) {
                            return data.responseData.translatedText;
                        }
                    }
                    throw new Error('Microsoft Translator failed');
                } catch (error) {
                    throw new Error(`Microsoft Translator error: ${error.message}`);
                }
            },
            
            // Method 3: Enhanced dictionary translation (always works)
            async () => {
                const result = this.getEnhancedTranslation(text, targetLanguage);
                if (result !== text) {
                    return result;
                }
                throw new Error('Dictionary translation had no matches');
            }
        ];

        // Try each method in order
        for (let i = 0; i < translationMethods.length; i++) {
            try {
                const result = await translationMethods[i]();
                if (result && result !== text && result.length > 0) {
                    console.log(`Translation successful using method ${i + 1}:`, result.substring(0, 50) + '...');
                    return result;
                }
            } catch (error) {
                console.warn(`Translation method ${i + 1} failed:`, error.message);
                continue;
            }
        }

        // If all methods fail, return original text
        console.warn('All translation methods failed for:', text.substring(0, 50) + '...');
        return text;
    }

    getTranslationLanguageCode(lang) {
        const langMap = {
            'zh': 'zh-CN',
            'ms': 'ms',
            'hi': 'hi'
        };
        return langMap[lang] || 'en';
    }

    getGoogleTranslateLanguageCode(lang) {
        const langMap = {
            'zh': 'zh-cn',
            'ms': 'ms',
            'hi': 'hi'
        };
        return langMap[lang] || 'en';
    }

    getMicrosoftLanguageCode(lang) {
        const langMap = {
            'zh': 'zh-CN',
            'ms': 'ms',
            'hi': 'hi'
        };
        return langMap[lang] || 'en';
    }

    getLibreTranslateLanguageCode(lang) {
        const langMap = {
            'zh': 'zh',
            'ms': 'ms',
            'hi': 'hi'
        };
        return langMap[lang] || 'en';
    }

    // Enhanced dictionary-based translation for common news terms
    getEnhancedTranslation(text, targetLanguage) {
        const translations = {
            zh: {
                'Singapore': '新加坡',
                'News': '新闻',
                'Update': '更新',
                'Weather': '天气',
                'Business': '商业',
                'Technology': '技术',
                'Health': '健康',
                'Community': '社区',
                'Government': '政府',
                'Market': '市场',
                'Digital': '数字',
                'Senior': '老年人',
                'Today': '今天',
                'Report': '报告'
            },
            ms: {
                'Singapore': 'Singapura',
                'News': 'Berita',
                'Update': 'Kemas Kini',
                'Weather': 'Cuaca',
                'Business': 'Perniagaan',
                'Technology': 'Teknologi',
                'Health': 'Kesihatan',
                'Community': 'Komuniti',
                'Government': 'Kerajaan',
                'Market': 'Pasar',
                'Digital': 'Digital',
                'Senior': 'Warga Emas',
                'Today': 'Hari Ini',
                'Report': 'Laporan'
            },
            hi: {
                'Singapore': 'सिंगापुर',
                'News': 'समाचार',
                'Update': 'अपडेट',
                'Weather': 'मौसम',
                'Business': 'व्यापार',
                'Technology': 'प्रौद्योगिकी',
                'Health': 'स्वास्थ्य',
                'Community': 'समुदाय',
                'Government': 'सरकार',
                'Market': 'बाजार',
                'Digital': 'डिजिटल',
                'Senior': 'वरिष्ठ',
                'Today': 'आज',
                'Report': 'रिपोर्ट'
            }
        };

        if (!translations[targetLanguage]) {
            return text;
        }

        let translatedText = text;
        const dict = translations[targetLanguage];
        
        // Replace common terms
        for (const [english, translated] of Object.entries(dict)) {
            const regex = new RegExp(`\\b${english}\\b`, 'gi');
            translatedText = translatedText.replace(regex, translated);
        }

        // If we made any replacements, return the result
        return translatedText !== text ? translatedText : text;
    }

    // Background image fetching for better performance
    async fetchRealImagesInBackground(articles) {
        // Fetch real images for a few articles in the background without blocking UI
        articles.forEach(async (article, index) => {
            if (article.needsImageFetch && article.url) {
                try {
                    const realImageUrl = await this.fetchImageFromArticle(article.url);
                    if (realImageUrl) {
                        // Update the image in the already displayed article
                        const newsCards = document.querySelectorAll('.news-card');
                        if (newsCards[index]) {
                            const img = newsCards[index].querySelector('.news-image');
                            if (img) {
                                img.src = realImageUrl;
                                // Ensure image maintains proper dimensions
                                img.style.width = '100%';
                                img.style.height = '200px';
                                img.style.objectFit = 'cover';
                            }
                        }
                    }
                } catch (error) {
                    console.warn('Background image fetch failed:', error);
                }
            }
        });
    }

    guessStraitTimesImage(articleUrl, index) {
        // This function is now replaced by fetchImageFromArticle
        return null;
    }

    getStraitsFallbackImage(source, index = 0) {
        // Multiple varied images per category to avoid repetition
        const fallbackImages = {
            'st-singapore': [
                'https://images.unsplash.com/photo-1525625293386-3f8f99389edd?w=400&h=200&fit=crop&crop=center', // Singapore skyline
                'https://images.unsplash.com/photo-1565967511849-76a60a516170?w=400&h=200&fit=crop&crop=center', // Marina Bay
                'https://images.unsplash.com/photo-1508964942454-1a56651d54ac?w=400&h=200&fit=crop&crop=center', // Singapore architecture
                'https://images.unsplash.com/photo-1555217851-6141535bd771?w=400&h=200&fit=crop&crop=center', // Singapore street
                'https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=400&h=200&fit=crop&crop=center'  // Singapore gardens
            ],
            'st-asia': [
                'https://images.unsplash.com/photo-1578662996442-48f60103fc96?w=400&h=200&fit=crop&crop=center', // Asian cityscape
                'https://images.unsplash.com/photo-1480796927426-f609979314bd?w=400&h=200&fit=crop&crop=center', // Asian architecture
                'https://images.unsplash.com/photo-1513475382585-d06e58bcb0e0?w=400&h=200&fit=crop&crop=center', // Asian culture
                'https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=400&h=200&fit=crop&crop=center', // Asian landscape
                'https://images.unsplash.com/photo-1521737711867-e3b97375f902?w=400&h=200&fit=crop&crop=center'  // Asian business
            ],
            'st-world': [
                'https://images.unsplash.com/photo-1506905925346-21bda4d32df4?w=400&h=200&fit=crop&crop=center', // World map
                'https://images.unsplash.com/photo-1451187580459-43490279c0fa?w=400&h=200&fit=crop&crop=center', // Globe
                'https://images.unsplash.com/photo-1569163139394-de4e4f43e4e3?w=400&h=200&fit=crop&crop=center', // Earth
                'https://images.unsplash.com/photo-1446776877081-d282a0f896e2?w=400&h=200&fit=crop&crop=center', // International
                'https://images.unsplash.com/photo-1504608524841-42fe6f032b4b?w=400&h=200&fit=crop&crop=center'  // Global news
            ],
            'st-business': [
                'https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?w=400&h=200&fit=crop&crop=center', // Business district
                'https://images.unsplash.com/photo-1507003211169-0a1dd7228f2d?w=400&h=200&fit=crop&crop=center', // Finance
                'https://images.unsplash.com/photo-1454165804606-c3d57bc86b40?w=400&h=200&fit=crop&crop=center', // Business meeting
                'https://images.unsplash.com/photo-1560472354-b33ff0c44a43?w=400&h=200&fit=crop&crop=center', // Stock market
                'https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=400&h=200&fit=crop&crop=center'  // Business growth
            ],
            'st-tech': [
                'https://images.unsplash.com/photo-1518709268805-4e9042af2176?w=400&h=200&fit=crop&crop=center', // Technology
                'https://images.unsplash.com/photo-1485827404703-89b55fcc595e?w=400&h=200&fit=crop&crop=center', // Programming
                'https://images.unsplash.com/photo-1551288049-bebda4e38f71?w=400&h=200&fit=crop&crop=center', // Digital
                'https://images.unsplash.com/photo-1504384308090-c894fdcc538d?w=400&h=200&fit=crop&crop=center', // Innovation
                'https://images.unsplash.com/photo-1460925895917-afdab827c52f?w=400&h=200&fit=crop&crop=center'  // Data
            ]
        };
        
        const categoryImages = fallbackImages[source] || fallbackImages['st-singapore'];
        return categoryImages[index % categoryImages.length];
    }

    getMockNews() {
        // Simplified mock news data that uses the translation system
        return [
            {
                title: "Singapore Implements New Digital Health Initiative",
                description: "The government announces a comprehensive digital health program to improve healthcare accessibility for elderly citizens.",
                urlToImage: "https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=400&h=200&fit=crop&crop=center",
                url: "#",
                source: { name: "Singapore Health News" },
                publishedAt: new Date().toISOString(),
                originalTitle: "Singapore Implements New Digital Health Initiative",
                originalDescription: "The government announces a comprehensive digital health program to improve healthcare accessibility for elderly citizens.",
                needsTranslation: true
            },
            {
                title: "Community Centers Launch Senior-Friendly Technology Classes",
                description: "Local community centers across Singapore are introducing technology literacy programs specifically designed for senior citizens.",
                urlToImage: "https://images.unsplash.com/photo-1522202176988-66273c2fd55f?w=400&h=200&fit=crop&crop=center",
                url: "#",
                source: { name: "Community Today" },
                publishedAt: new Date(Date.now() - 3600000).toISOString(),
                originalTitle: "Community Centers Launch Senior-Friendly Technology Classes",
                originalDescription: "Local community centers across Singapore are introducing technology literacy programs specifically designed for senior citizens.",
                needsTranslation: true
            },
            {
                title: "Weather Update: Sunny Skies Expected This Week",
                description: "Meteorological services predict pleasant weather conditions with temperatures ranging from 26-32°C throughout the week.",
                urlToImage: "https://images.unsplash.com/photo-1504608524841-42fe6f032b4b?w=400&h=200&fit=crop&crop=center",
                url: "#",
                source: { name: "Weather Singapore" },
                publishedAt: new Date(Date.now() - 7200000).toISOString(),
                originalTitle: "Weather Update: Sunny Skies Expected This Week",
                originalDescription: "Meteorological services predict pleasant weather conditions with temperatures ranging from 26-32°C throughout the week.",
                needsTranslation: true
            },
            {
                title: "Local Markets Report Fresh Produce Availability",
                description: "Wet markets and supermarkets report good availability of fresh fruits and vegetables with stable pricing.",
                urlToImage: "https://images.unsplash.com/photo-1542838132-92c53300491e?w=400&h=200&fit=crop&crop=center",
                url: "#",
                source: { name: "Market Watch" },
                publishedAt: new Date(Date.now() - 10800000).toISOString(),
                originalTitle: "Local Markets Report Fresh Produce Availability",
                originalDescription: "Wet markets and supermarkets report good availability of fresh fruits and vegetables with stable pricing.",
                needsTranslation: true
            }
        ];
    }

    getStraitsMockNews() {
        // Fallback Straits Times news data when RSS fails
        const categoryMap = {
            'st-singapore': [
                {
                    title: "Singapore Rolls Out Enhanced Digital Services for Seniors",
                    description: "The government launches new digital initiatives to help elderly residents access essential services more easily through simplified online platforms.",
                    urlToImage: "https://images.unsplash.com/photo-1559757148-5c350d0d3c56?w=400&h=200&fit=crop&crop=center",
                    url: "#",
                    source: { name: "The Straits Times" },
                    publishedAt: new Date().toISOString()
                },
                {
                    title: "New MRT Line Extension to Benefit Eastern Singapore",
                    description: "Transport authorities announce plans for extending the MRT network to better serve residents in eastern districts with improved connectivity.",
                    urlToImage: "https://images.unsplash.com/photo-1544620347-c4fd4a3d5957?w=400&h=200&fit=crop&crop=center",
                    url: "#",
                    source: { name: "The Straits Times" },
                    publishedAt: new Date(Date.now() - 3600000).toISOString()
                }
            ],
            'st-asia': [
                {
                    title: "ASEAN Leaders Discuss Regional Economic Cooperation",
                    description: "Southeast Asian leaders convene to strengthen economic ties and discuss collaborative initiatives for regional development and trade enhancement.",
                    urlToImage: "https://images.unsplash.com/photo-1521737711867-e3b97375f902?w=400&h=200&fit=crop&crop=center",
                    url: "#",
                    source: { name: "The Straits Times" },
                    publishedAt: new Date().toISOString()
                },
                {
                    title: "Malaysia and Singapore Strengthen Cross-Border Collaboration",
                    description: "Both nations announce new initiatives to enhance cooperation in areas including healthcare, education, and sustainable development.",
                    urlToImage: "https://images.unsplash.com/photo-1497436072909-f5e4be1713a0?w=400&h=200&fit=crop&crop=center",
                    url: "#",
                    source: { name: "The Straits Times" },
                    publishedAt: new Date(Date.now() - 7200000).toISOString()
                }
            ],
            'st-world': [
                {
                    title: "Global Climate Summit Addresses Urgent Environmental Challenges",
                    description: "World leaders gather to discuss comprehensive strategies for addressing climate change and implementing sustainable development goals.",
                    urlToImage: "https://images.unsplash.com/photo-1569163139394-de4e4f43e4e3?w=400&h=200&fit=crop&crop=center",
                    url: "#",
                    source: { name: "The Straits Times" },
                    publishedAt: new Date().toISOString()
                }
            ],
            'st-business': [
                {
                    title: "Singapore's Financial Sector Shows Robust Growth",
                    description: "Local banks and financial institutions report strong performance as the city-state continues to attract international investments and businesses.",
                    urlToImage: "https://images.unsplash.com/photo-1486406146926-c627a92ad1ab?w=400&h=200&fit=crop&crop=center",
                    url: "#",
                    source: { name: "The Straits Times" },
                    publishedAt: new Date().toISOString()
                }
            ],
            'st-tech': [
                {
                    title: "Singapore Advances Smart Nation Initiative with AI Integration",
                    description: "The government unveils new artificial intelligence applications designed to improve urban planning, healthcare delivery, and public services.",
                    urlToImage: "https://images.unsplash.com/photo-1518709268805-4e9042af2176?w=400&h=200&fit=crop&crop=center",
                    url: "#",
                    source: { name: "The Straits Times" },
                    publishedAt: new Date().toISOString()
                }
            ]
        };

        return categoryMap[this.currentSource] || categoryMap['st-singapore'];
    }

    getLanguageCode() {
        const languageMap = {
            'en': 'en',
            'zh': 'zh',
            'ms': 'en', // NewsAPI doesn't support Malay, fallback to English
            'hi': 'en'  // NewsAPI doesn't support Hindi, fallback to English
        };
        return languageMap[this.currentLanguage] || 'en';
    }

    displayNews(articles) {
        const newsGrid = document.getElementById('newsGrid');
        newsGrid.innerHTML = '';

        if (!articles || articles.length === 0) {
            newsGrid.innerHTML = '<p style="text-align: center; font-size: 18px; color: #666;">No news articles available at the moment.</p>';
            return;
        }

        articles.forEach(article => {
            const newsCard = this.createNewsCard(article);
            newsGrid.appendChild(newsCard);
        });
    }

    createNewsCard(article) {
        const card = document.createElement('div');
        card.className = 'news-card';
        
        const publishedDate = new Date(article.publishedAt).toLocaleDateString(this.getLocale());
        
        card.innerHTML = `
            <div class="news-image-container">
                <img src="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='400' height='200'%3E%3Crect width='100%25' height='100%25' fill='%23e9ecef'/%3E%3Ctext x='50%25' y='50%25' dominant-baseline='middle' text-anchor='middle' fill='%23666' font-family='Arial' font-size='16'%3ELoading...%3C/text%3E%3C/svg%3E" alt="${article.title}" class="news-image" id="img-${Date.now()}-${Math.random()}">
            </div>
            <div class="news-content">
                <h3 class="news-title">${article.title}</h3>
                <p class="news-description">${article.description || 'No description available.'}</p>
                <div class="news-meta">
                    <span class="news-source">${article.source.name}</span>
                    <span class="news-date">${publishedDate}</span>
                </div>
            </div>
        `;

        // Handle image loading
        const img = card.querySelector('.news-image');
        if (article.urlToImage) {
            // Set image source directly
            img.src = article.urlToImage;
            // Ensure consistent image dimensions
            img.style.width = '70%';
            img.style.height = '200px';
            img.style.objectFit = 'cover';
            
            // Add error handler in case image fails to load
            img.onerror = () => {
                // Fallback to a simple colored rectangle
                img.src = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='400' height='200'%3E%3Crect width='100%25' height='100%25' fill='%23667eea'/%3E%3Ctext x='50%25' y='50%25' dominant-baseline='middle' text-anchor='middle' fill='white' font-family='Arial' font-size='18' font-weight='bold'%3E📰 News%3C/text%3E%3C/svg%3E`;
            };
        } else {
            // No image provided, use default
            img.src = `data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='400' height='200'%3E%3Crect width='100%25' height='100%25' fill='%23667eea'/%3E%3Ctext x='50%25' y='50%25' dominant-baseline='middle' text-anchor='middle' fill='white' font-family='Arial' font-size='18' font-weight='bold'%3E📰 News%3C/text%3E%3C/svg%3E`;
        }

        // Add click event to open article
        card.addEventListener('click', () => {
            if (article.url && article.url !== '#') {
                window.open(article.url, '_blank');
            }
        });

        return card;
    }

    getLocale() {
        const localeMap = {
            'en': 'en-US',
            'zh': 'zh-CN',
            'ms': 'ms-MY',
            'hi': 'hi-IN'
        };
        return localeMap[this.currentLanguage] || 'en-US';
    }

    showLoading() {
        document.getElementById('loading').style.display = 'block';
        document.getElementById('newsGrid').style.display = 'none';
    }

    hideLoading() {
        document.getElementById('loading').style.display = 'none';
        document.getElementById('newsGrid').style.display = 'grid';
    }

    showError() {
        document.getElementById('errorMessage').style.display = 'block';
        document.getElementById('newsGrid').style.display = 'none';
    }

    hideError() {
        document.getElementById('errorMessage').style.display = 'none';
    }

    savePreferences() {
        localStorage.setItem('preferredLanguage', this.currentLanguage);
        localStorage.setItem('preferredNewsSource', this.currentSource);
    }
}

// Initialize the app when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new NewsletterApp();
});
