(() => {
  const loginPath = '/admin/';
  const isLoginPage = /\/admin\/?$|\/admin\/index\.html$/.test(window.location.pathname);
  if (!isLoginPage) {
    document.documentElement.style.visibility = 'hidden';
    fetch('/api/auth/session', { credentials: 'same-origin' })
      .then(response => response.json())
      .then(session => {
        if (!session.authenticated) {
          window.location.replace(loginPath);
          return;
        }
        document.documentElement.style.visibility = '';
        document.querySelectorAll('.topbar-user-name, .sidebar-footer .user-name').forEach(target => { target.textContent = session.email; });
        document.querySelectorAll('.sidebar-footer .user-role').forEach(target => { target.textContent = 'Administrator'; });
        const accountName = session.email.split('@')[0];
        const initials = accountName === 'admin' ? 'AD' : accountName.split(/[._-]/).filter(Boolean).map(part => part[0]).join('').slice(0, 2).toUpperCase() || 'AD';
        document.querySelectorAll('.user-avatar, .topbar-user-avatar').forEach(target => { target.textContent = initials; });
        fetch('/api/stats', { credentials: 'same-origin' })
          .then(response => response.ok ? response.json() : null)
          .then(stats => {
            if (!stats) return;
            const complaintBadge = document.querySelector('[id="sidebarPendingComplaints"]');
            const bursaryBadge = document.querySelector('[id="sidebarPendingBursaries"]');
            if (complaintBadge) complaintBadge.textContent = stats.pendingComplaints || 0;
            if (bursaryBadge) bursaryBadge.textContent = stats.pendingBursaries || 0;
          })
          .catch(() => {});
      })
      .catch(() => window.location.replace(loginPath));
  }

  window.adminFetch = async (url, options = {}) => {
    const response = await fetch(url, { ...options, credentials: 'same-origin' });
    if (response.status === 401) {
      window.location.replace(loginPath);
      throw new Error('Your admin session has expired');
    }
    return response;
  };

  document.addEventListener('click', async event => {
    const logout = event.target.closest('.logout-btn');
    if (!logout) return;
    event.preventDefault();
    try { await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' }); } finally {
      window.location.replace(loginPath);
    }
  });
})();