// Helper functions for authentication
class AuthHelper {
  static async checkLoginStatus() {
    try {
      const token = localStorage.getItem('authToken');
      const user = JSON.parse(localStorage.getItem('decimeterUser'));
      
      if (!token || !user) {
        this.clearAuth();
        return false;
      }
      
      // Verify token with server
      const response = await fetch('/.netlify/functions/auth', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          action: 'verify',
          token: token
        })
      });
      
      const data = await response.json();
      
      if (data.success && data.user) {
        // Update user data if needed
        const updatedUser = {
          ...user,
          id: data.user.id,
          email: data.user.email,
          name: data.user.name,
          firstName: data.user.firstName,
          lastName: data.user.lastName,
          phone: data.user.phone,
          loggedIn: true
        };
        
        localStorage.setItem('decimeterUser', JSON.stringify(updatedUser));
        
        // Update UI
        this.updateAuthUI(updatedUser);
        return true;
      } else {
        this.clearAuth();
        return false;
      }
      
    } catch (error) {
      console.error('Auth check error:', error);
      this.clearAuth();
      return false;
    }
  }
  
  static updateAuthUI(user) {
    const loginLink = document.getElementById('loginLink');
    const userInfo = document.getElementById('userInfo');
    const userName = document.getElementById('userName');
    
    if (loginLink) loginLink.style.display = 'none';
    if (userInfo) userInfo.style.display = 'flex';
    if (userName) userName.textContent = user.name || user.email;
  }
  
  static clearAuthUI() {
    const loginLink = document.getElementById('loginLink');
    const userInfo = document.getElementById('userInfo');
    
    if (loginLink) loginLink.style.display = 'block';
    if (userInfo) userInfo.style.display = 'none';
  }
  
  static clearAuth() {
    localStorage.removeItem('decimeterUser');
    localStorage.removeItem('authToken');
    this.clearAuthUI();
  }
  
  static async logout() {
    // You can add server-side logout logic here if needed
    this.clearAuth();
    window.location.reload();
  }
  
  static requireAuth(redirectUrl = 'login.html') {
    if (!localStorage.getItem('authToken')) {
      window.location.href = `${redirectUrl}?redirect=${encodeURIComponent(window.location.pathname)}`;
      return false;
    }
    return true;
  }
  
  static getUser() {
    const user = localStorage.getItem('decimeterUser');
    return user ? JSON.parse(user) : null;
  }
  
  static getToken() {
    return localStorage.getItem('authToken');
  }
}