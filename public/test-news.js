// Simple test script to verify the news API is working
document.addEventListener('DOMContentLoaded', () => {
    console.log('Test script loaded');
    
    // Get references to DOM elements
    const loadingElement = document.getElementById('loading');
    const errorElement = document.getElementById('errorMessage');
    const newsGridElement = document.getElementById('newsGrid');
    
    // Function to show loading indicator
    function showLoading() {
        loadingElement.style.display = 'flex';
        errorElement.style.display = 'none';
    }
    
    // Function to hide loading indicator
    function hideLoading() {
        loadingElement.style.display = 'none';
    }
    
    // Function to show error message
    function showError() {
        errorElement.style.display = 'block';
    }
    
    // Function to create a news card
    function createNewsCard(article) {
        const card = document.createElement('div');
        card.className = 'news-card';
        
        const image = document.createElement('img');
        image.className = 'news-image';
        image.src = article.urlToImage || 'https://via.placeholder.com/400x200?text=No+Image';
        image.alt = article.title;
        
        const content = document.createElement('div');
        content.className = 'news-content';
        
        const source = document.createElement('div');
        source.className = 'news-source';
        source.textContent = article.source?.name || 'Unknown Source';
        
        const title = document.createElement('h3');
        title.className = 'news-title';
        title.textContent = article.title;
        
        const description = document.createElement('p');
        description.className = 'news-description';
        description.textContent = article.description || 'No description available';
        
        content.appendChild(source);
        content.appendChild(title);
        content.appendChild(description);
        
        card.appendChild(image);
        card.appendChild(content);
        
        return card;
    }
    
    // Function to display news
    function displayNews(articles) {
        newsGridElement.innerHTML = '';
        
        if (!articles || articles.length === 0) {
            const message = document.createElement('p');
            message.className = 'no-news';
            message.textContent = 'No news articles available.';
            newsGridElement.appendChild(message);
            return;
        }
        
        articles.forEach(article => {
            const card = createNewsCard(article);
            newsGridElement.appendChild(card);
        });
    }
    
    // Function to load news
    async function loadNews() {
        showLoading();
        
        try {
            console.log('Fetching news from /api/news');
            const response = await fetch('/api/news');
            
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            
            const data = await response.json();
            console.log('News data received:', data);
            
            if (data && data.articles) {
                displayNews(data.articles);
            } else {
                throw new Error('Invalid data format');
            }
        } catch (error) {
            console.error('Error loading news:', error);
            showError();
        } finally {
            hideLoading();
        }
    }
    
    // Load news when page loads
    loadNews();
    
    // Add event listener to refresh button
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', loadNews);
    }
    
    // Add event listener to retry button
    const retryBtn = document.getElementById('retryBtn');
    if (retryBtn) {
        retryBtn.addEventListener('click', loadNews);
    }
});
