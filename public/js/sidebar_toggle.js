document.addEventListener('DOMContentLoaded', () => {
  const themeToggle = document.getElementById('themeToggle');
  const collapseToggle = document.getElementById('collapseToggle');
  const sidebar = document.getElementById('adminSidebar');

  // Load saved theme
  const savedTheme = localStorage.getItem('adminSidebarTheme');
  if (savedTheme === 'light') {
    sidebar.classList.remove('dark');
    sidebar.classList.add('light');
  }

  // Load collapse state
  const isCollapsed = localStorage.getItem('sidebarCollapsed') === 'true';
  if (isCollapsed) {
    sidebar.classList.add('collapsed');
  }

  // Theme Toggle
  themeToggle.addEventListener('click', () => {
    sidebar.classList.toggle('dark');
    sidebar.classList.toggle('light');
    const isLight = sidebar.classList.contains('light');
    localStorage.setItem('adminSidebarTheme', isLight ? 'light' : 'dark');
  });

  // Collapse Toggle
  collapseToggle.addEventListener('click', () => {
    sidebar.classList.toggle('collapsed');
    localStorage.setItem('sidebarCollapsed', sidebar.classList.contains('collapsed'));
  });

  // Activate Lucide Icons
  lucide.createIcons();
});
