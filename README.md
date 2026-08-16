# Nour's Security Notes

Personal cybersecurity write-up blog built with the [Chirpy Jekyll theme](https://github.com/cotes2020/jekyll-theme-chirpy) and designed for deployment through GitHub Pages.

## Publish on GitHub Pages

This repository is configured for the GitHub user site:

`https://nourbrinsa.github.io`

1. Push these files to the `main` branch of the `nourbrinsa.github.io` repository.
2. On GitHub, open **Settings → Pages**.
3. Under **Build and deployment → Source**, select **GitHub Actions**.
4. Push a commit if the deployment workflow has not already started.
5. Open the **Actions** tab and confirm that **Build and Deploy** succeeds.

The deployment workflow is already included at `.github/workflows/pages-deploy.yml`.

## Run locally

Requirements: Ruby, Bundler, and Git.

```bash
bundle install
bundle exec jekyll serve
```

Then open `http://127.0.0.1:4000`.

The included helper also works on Linux/macOS:

```bash
bash tools/run.sh
```

## Add a new write-up

Create a Markdown file under `_posts/` using the Jekyll filename format:

```text
YYYY-MM-DD-short-post-name.md
```

Example front matter:

```yaml
---
title: "Machine Name — Platform Writeup"
date: 2026-08-16 18:00:00 +0200
categories: [Writeups, TryHackMe]
tags: [tryhackme, linux, web-security]
description: "Short description used in previews and SEO metadata."
toc: true
---
```

Write normal Markdown below the closing `---`.

## Add screenshots

Store screenshots for each post in a dedicated folder, for example:

```text
assets/img/posts/breakme/
```

If the post has this front-matter field:

```yaml
media_subpath: /assets/img/posts/breakme
```

then an image can be inserted with:

```markdown
![WPScan plugin discovery](wpscanplugin.png)
```

Use descriptive alt text rather than generic labels such as "image".

## Main files you will normally edit

- `_config.yml` — site title, URL, identity, global behavior.
- `_tabs/about.md` — About page.
- `_data/contact.yml` — sidebar contact icons.
- `_posts/` — published blog posts.
- `assets/img/posts/` — post screenshots and images.

## Current first post

`_posts/2026-08-09-breakme-tryhackme-writeup.md`

The screenshots listed in the original report were not part of the uploaded files, so the post is intentionally configured to render without them. A placeholder directory and filename list are included under `assets/img/posts/breakme/README.md`.
