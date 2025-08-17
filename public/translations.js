// Multi-language translations for the newsletter app
const translations = {
    en: {
        language: "Language:",
        newsSource: "News Source:",
        refresh: "🔄 Refresh News",
        loading: "Loading news...",
        error: "Unable to load news. Please try again later.",
        retry: "Try Again",
        footer: "© 2024 Newsletter App - News for Everyone",
        readMore: "Read More",
        publishedAt: "Published:",
        source: "Source:",
        noImage: "No image available",
        generalNews: "General News",
        stSingapore: "Straits Times - Singapore",
        stAsia: "Straits Times - Asia",
        stWorld: "Straits Times - World",
        stBusiness: "Straits Times - Business",
        stTech: "Straits Times - Tech",
        bbcNews: "BBC News",
        cnn: "CNN",
        reuters: "Reuters",
        associatedPress: "Associated Press",
        timesOfIndia: "Times of India"
    },
    zh: {
        language: "语言:",
        newsSource: "新闻来源:",
        refresh: "🔄 刷新新闻",
        loading: "正在加载新闻...",
        error: "无法加载新闻。请稍后再试。",
        retry: "重试",
        footer: "© 2024 新闻应用 - 为每个人提供新闻",
        readMore: "阅读更多",
        publishedAt: "发布时间:",
        source: "来源:",
        noImage: "无图片",
        generalNews: "综合新闻",
        stSingapore: "海峡时报 - 新加坡",
        stAsia: "海峡时报 - 亚洲",
        stWorld: "海峡时报 - 世界",
        stBusiness: "海峡时报 - 商业",
        stTech: "海峡时报 - 科技",
        bbcNews: "BBC新闻",
        cnn: "CNN",
        reuters: "路透社",
        associatedPress: "美联社",
        timesOfIndia: "印度时报"
    },
    ms: {
        language: "Bahasa:",
        newsSource: "Sumber Berita:",
        refresh: "🔄 Muat Semula Berita",
        loading: "Memuatkan berita...",
        error: "Tidak dapat memuatkan berita. Sila cuba lagi nanti.",
        retry: "Cuba Lagi",
        footer: "© 2024 Aplikasi Berita - Berita untuk Semua",
        readMore: "Baca Lagi",
        publishedAt: "Diterbitkan:",
        source: "Sumber:",
        noImage: "Tiada imej tersedia",
        generalNews: "Berita Umum",
        stSingapore: "Straits Times - Singapura",
        stAsia: "Straits Times - Asia",
        stWorld: "Straits Times - Dunia",
        stBusiness: "Straits Times - Perniagaan",
        stTech: "Straits Times - Teknologi",
        bbcNews: "Berita BBC",
        cnn: "CNN",
        reuters: "Reuters",
        associatedPress: "Associated Press",
        timesOfIndia: "Times of India"
    },
    hi: {
        language: "भाषा:",
        newsSource: "समाचार स्रोत:",
        refresh: "🔄 समाचार रीफ्रेश करें",
        loading: "समाचार लोड हो रहे हैं...",
        error: "समाचार लोड नहीं हो सके। कृपया बाद में पुनः प्रयास करें।",
        retry: "पुनः प्रयास करें",
        footer: "© 2024 समाचार ऐप - सभी के लिए समाचार",
        readMore: "और पढ़ें",
        publishedAt: "प्रकाशित:",
        source: "स्रोत:",
        noImage: "कोई छवि उपलब्ध नहीं",
        generalNews: "सामान्य समाचार",
        stSingapore: "स्ट्रेट्स टाइम्स - सिंगापुर",
        stAsia: "स्ट्रेट्स टाइम्स - एशिया",
        stWorld: "स्ट्रेट्स टाइम्स - विश्व",
        stBusiness: "स्ट्रेट्स टाइम्स - व्यापार",
        stTech: "स्ट्रेट्स टाइम्स - प्रौद्योगिकी",
        bbcNews: "बीबीसी समाचार",
        cnn: "सीएनएन",
        reuters: "रॉयटर्स",
        associatedPress: "एसोसिएटेड प्रेस",
        timesOfIndia: "टाइम्स ऑफ इंडिया"
    }
};

// Function to update UI text based on selected language
function updateLanguage(lang) {
    const elements = document.querySelectorAll('[data-translate]');
    elements.forEach(element => {
        const key = element.getAttribute('data-translate');
        if (translations[lang] && translations[lang][key]) {
            element.textContent = translations[lang][key];
        }
    });
    
    // Update news source options
    updateNewsSourceOptions(lang);
    
    // Store language preference
    localStorage.setItem('preferredLanguage', lang);
}

// Function to update news source dropdown options
function updateNewsSourceOptions(lang) {
    const newsSelect = document.getElementById('newsSource');
    const currentValue = newsSelect.value;
    
    // Clear existing options
    newsSelect.innerHTML = '';
    
    // Add options with translated labels
    const sources = [
        { value: 'general', key: 'generalNews' },
        { value: 'st-singapore', key: 'stSingapore' },
        { value: 'st-asia', key: 'stAsia' },
        { value: 'st-world', key: 'stWorld' },
        { value: 'st-business', key: 'stBusiness' },
        { value: 'st-tech', key: 'stTech' },
        { value: 'bbc-news', key: 'bbcNews' },
        { value: 'cnn', key: 'cnn' },
        { value: 'reuters', key: 'reuters' },
        { value: 'associated-press', key: 'associatedPress' },
        { value: 'the-times-of-india', key: 'timesOfIndia' }
    ];
    
    sources.forEach(source => {
        const option = document.createElement('option');
        option.value = source.value;
        option.textContent = translations[lang][source.key] || source.key;
        newsSelect.appendChild(option);
    });
    
    // Restore previous selection
    newsSelect.value = currentValue;
}

// Initialize language on page load
document.addEventListener('DOMContentLoaded', function() {
    const savedLanguage = localStorage.getItem('preferredLanguage') || 'en';
    const languageSelect = document.getElementById('language');
    languageSelect.value = savedLanguage;
    updateLanguage(savedLanguage);
});
