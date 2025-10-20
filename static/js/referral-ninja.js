// Referral Ninja Interactive Features
class ReferralNinja {
    constructor() {
        this.init();
    }
    
    init() {
        this.initSidebarInteractions();
        this.initStatsAnimations();
        this.initCopyFunctions();
        this.initRealTimeUpdates();
        this.initThemeSwitcher();
    }
    
    initSidebarInteractions() {
        const navItems = document.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            item.addEventListener('click', function(e) {
                navItems.forEach(nav => nav.classList.remove('active'));
                this.classList.add('active');
                
                const ripple = document.createElement('span');
                const rect = this.getBoundingClientRect();
                const size = Math.max(rect.width, rect.height);
                const x = e.clientX - rect.left - size / 2;
                const y = e.clientY - rect.top - size / 2;
                
                ripple.style.cssText = `
                    width: ${size}px;
                    height: ${size}px;
                    left: ${x}px;
                    top: ${y}px;
                `;
                ripple.classList.add('ripple-effect');
                this.appendChild(ripple);
                
                setTimeout(() => ripple.remove(), 600);
            });
        });
    }
    
    initStatsAnimations() {
        const counters = document.querySelectorAll('.stat-card h3');
        counters.forEach(counter => {
            const target = this.extractNumber(counter.textContent);
            this.animateValue(counter, 0, target, 2000);
        });
    }
    
    animateValue(element, start, end, duration) {
        let startTimestamp = null;
        const step = (timestamp) => {
            if (!startTimestamp) startTimestamp = timestamp;
            const progress = Math.min((timestamp - startTimestamp) / duration, 1);
            const value = Math.floor(progress * (end - start) + start);
            element.textContent = this.formatNumber(value);
            if (progress < 1) {
                window.requestAnimationFrame(step);
            }
        };
        window.requestAnimationFrame(step);
    }
    
    extractNumber(text) {
        return parseInt(text.replace(/[^\d]/g, '')) || 0;
    }
    
    formatNumber(num) {
        if (num >= 1000) {
            return 'KSH ' + (num / 1000).toFixed(1) + 'K';
        }
        return 'KSH ' + num;
    }
    
    initCopyFunctions() {
        window.copyReferralCode = function() {
            const codeElement = document.getElementById('referralCode');
            const code = codeElement?.getAttribute('data-code') || '{{ current_user.referral_code }}';
            
            navigator.clipboard.writeText(code).then(() => {
                this.showNotification('Referral code copied to clipboard!', 'success');
                
                if (codeElement) {
                    codeElement.classList.add('copied');
                    setTimeout(() => codeElement.classList.remove('copied'), 2000);
                }
            }).catch(() => {
                this.showNotification('Failed to copy referral code', 'error');
            });
        }.bind(this);
    }
    
    showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `notification ${type}`;
        notification.innerHTML = `
            <i class="fas fa-${type === 'success' ? 'check' : 'info'}"></i>
            <span>${message}</span>
        `;
        
        document.body.appendChild(notification);
        
        setTimeout(() => notification.classList.add('show'), 100);
        
        setTimeout(() => {
            notification.classList.remove('show');
            setTimeout(() => notification.remove(), 300);
        }, 3000);
    }
    
    initRealTimeUpdates() {
        setInterval(() => {
            this.updateLiveStats();
        }, 30000);
    }
    
    async updateLiveStats() {
        try {
            const response = await fetch('/api/live-stats');
            const data = await response.json();
            
            this.updateStatCard('.earnings-card h3', data.balance);
            this.updateStatCard('.referrals-card h3', data.total_referrals);
        } catch (error) {
            console.error('Failed to update live stats:', error);
        }
    }
    
    updateStatCard(selector, newValue) {
        const element = document.querySelector(selector);
        if (element) {
            const currentValue = this.extractNumber(element.textContent);
            if (currentValue !== newValue) {
                this.animateValue(element, currentValue, newValue, 1000);
            }
        }
    }
    
    initThemeSwitcher() {
        const themeToggle = document.getElementById('themeToggle');
        if (themeToggle) {
            themeToggle.addEventListener('click', () => {
                document.body.classList.toggle('dark-theme');
                const isDark = document.body.classList.contains('dark-theme');
                localStorage.setItem('theme', isDark ? 'dark' : 'light');
            });
        }
        
        // Load saved theme
        const savedTheme = localStorage.getItem('theme');
        if (savedTheme === 'dark') {
            document.body.classList.add('dark-theme');
        }
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new ReferralNinja();
});

// Global functions
window.shareReferralLink = function() {
    const referralCode = document.getElementById('referralCode')?.getAttribute('data-code') || '{{ current_user.referral_code }}';
    const shareText = `Join Referral Ninja and start earning! Use my code: ${referralCode} - Earn KSH 50 for every friend who joins!`;
    const shareUrl = `${window.location.origin}/register?ref=${referralCode}`;
    
    if (navigator.share) {
        navigator.share({
            title: 'Referral Ninja',
            text: shareText,
            url: shareUrl
        });
    } else {
        navigator.clipboard.writeText(`${shareText} ${shareUrl}`).then(() => {
            alert('Referral link copied to clipboard!');
        });
    }
};