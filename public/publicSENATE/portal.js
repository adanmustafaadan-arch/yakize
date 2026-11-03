const hamburger = document.getElementById('hamburger');
const navLinks = document.getElementById('navLinks');
hamburger.addEventListener('click', () => navLinks.classList.toggle('open'));
document.querySelectorAll('.nav-link').forEach(link => link.addEventListener('click', () => navLinks.classList.remove('open')));

window.addEventListener('scroll', () => {
  document.getElementById('navbar').style.boxShadow = window.scrollY > 10 ? '0 4px 30px rgba(9,29,66,0.4)' : '';
});

function formatMoney(value) {
  return `KES ${Number(value || 0).toLocaleString()}`;
}

function projectStatus(status) {
  return { planned: 'Planning', active: 'In Progress', completed: 'Completed', delayed: 'Delayed', stalled: 'Stalled', cancelled: 'Cancelled' }[status] || 'Planning';
}

function projectVisual(category) {
  return {
    Roads: ['🛣️', 'linear-gradient(135deg,#0d2b5e,#1a3f7a)'],
    Water: ['💧', 'linear-gradient(135deg,#0f6e56,#1d9e75)'],
    Education: ['📚', 'linear-gradient(135deg,#c9a227,#e8b93a)'],
    Health: ['🏥', 'linear-gradient(135deg,#993c1d,#d85a30)'],
  }[category] || ['📍', 'linear-gradient(135deg,#185fa5,#378add)'];
}

function renderProjects(projects) {
  const container = document.getElementById('featuredProjects');
  container.replaceChildren();
  if (!projects.length) {
    container.textContent = 'No published projects are available.';
    return;
  }

  projects.slice(0, 3).forEach(project => {
    const category = project.department || project.category || 'Projects';
    const [icon, background] = projectVisual(category);
    const progress = Math.max(0, Math.min(100, Number(project.progress) || 0));
    const card = document.createElement('article');
    card.className = 'project-card';
    card.innerHTML = `<div class="project-img" style="background:${background}"><span class="project-ward-badge"></span><div class="project-img-icon">${icon}</div></div><div class="project-body"><h3></h3><div class="project-meta"><span class="project-location"></span><span class="project-budget"></span></div><div class="progress-wrap"><div class="progress-bar"><div class="progress-fill"></div></div><span class="progress-value"></span></div><span class="status-badge"></span></div>`;
    card.querySelector('.project-ward-badge').textContent = project.ward || 'County project';
    card.querySelector('h3').textContent = project.name || 'Project';
    card.querySelector('.project-location').textContent = `📍 ${project.ward || 'County-wide'}`;
    card.querySelector('.project-budget').textContent = formatMoney(project.budget);
    card.querySelector('.progress-fill').style.width = `${progress}%`;
    card.querySelector('.progress-value').textContent = `${progress}%`;
    const status = projectStatus(project.status);
    const badge = card.querySelector('.status-badge');
    badge.textContent = status;
    badge.classList.add(status === 'Completed' ? 'status-done' : 'status-active');
    container.appendChild(card);
  });
}

function renderNews(articles) {
  const container = document.getElementById('publicNews');
  container.replaceChildren();
  if (!articles.length) {
    container.textContent = 'No published news is available.';
    return;
  }

  articles.slice(0, 4).forEach((article, index) => {
    const card = document.createElement('article');
    card.className = `news-card${index === 0 ? ' news-featured' : ''}`;
    const tag = document.createElement('div');
    tag.className = 'news-tag';
    tag.textContent = article.category || 'County Update';
    const title = document.createElement('h3');
    title.textContent = article.title || 'County Update';
    const summary = document.createElement('p');
    summary.textContent = article.summary || article.body || '';
    const meta = document.createElement('div');
    meta.className = 'news-meta';
    const date = document.createElement('span');
    date.textContent = article.createdAt ? new Date(article.createdAt).toLocaleDateString() : '';
    meta.appendChild(date);
    card.append(tag, title, summary, meta);
    container.appendChild(card);
  });
}

async function loadPublicPortal() {
  const responses = await Promise.all([
    fetch('/api/public/stats'),
    fetch('/api/projects/public'),
    fetch('/api/news'),
  ]);
  if (responses.some(response => !response.ok)) throw new Error('Portal data is temporarily unavailable.');
  const [stats, projects, news] = await Promise.all(responses.map(response => response.json()));
  document.getElementById('heroComplaints').textContent = Number(stats.totalComplaints || 0).toLocaleString();
  document.getElementById('heroProjects').textContent = Number(stats.activeProjects || 0).toLocaleString();
  document.getElementById('heroBursaries').textContent = Number(stats.approvedBursaries || 0).toLocaleString();
  document.getElementById('publicComplaints').textContent = Number(stats.totalComplaints || 0).toLocaleString();
  document.getElementById('publicProjects').textContent = Number(stats.activeProjects || 0).toLocaleString();
  document.getElementById('publicBursaries').textContent = Number(stats.approvedBursaries || 0).toLocaleString();
  renderProjects(projects);
  renderNews(news);
}

loadPublicPortal().catch(error => {
  document.getElementById('featuredProjects').textContent = error.message;
  document.getElementById('publicNews').textContent = error.message;
});