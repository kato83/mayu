# Git Worktree Workflow

## Overview

This project uses `git worktree` to enable parallel development across multiple feature branches.
Each worktree can have its own Kiro session running independently.

## Directory Layout

```
~/git/
├── mayu/                          # Main worktree (main branch)
│   ├── .git/                      # Actual git directory
│   └── ...
└── mayu-worktree/
    ├── feature-api/               # Worktree: Phase 4 API Server
    ├── feature-webui/             # Worktree: Phase 5 Web UI
    └── fix-search-crash/          # Worktree: Bug fix
```

### Naming Convention

Worktree directory: `~/git/mayu-worktree/{type}-{short-description}`

- type: `feature`, `fix`, `refactor`, `chore`
- short-description: brief kebab-case English description

Branch name follows the same pattern: `{type}/{short-description}` (e.g., `feature/api-server`)

## Worktree Operations

### Create a new worktree

```bash
# Run from the main worktree
cd ~/git/mayu

# Ensure the parent directory exists
mkdir -p ~/git/mayu-worktree

# Create worktree with a new branch
git worktree add ~/git/mayu-worktree/feature-api -b feature/api-server

# Use an existing branch
git worktree add ~/git/mayu-worktree/fix-search feature/fix-search
```

### List worktrees

```bash
git worktree list
```

### Remove a worktree

```bash
# Ensure the branch has been merged first
cd ~/git/mayu
git worktree remove ~/git/mayu-worktree/feature-api
```

## Rules for Parallel Work

### Shared Database

- Docker PostgreSQL is started **once from the main worktree's compose.yml**
- All worktrees share the same `DATABASE_URL` (`localhost:5432`)
- Run migrations **only from the main worktree** to prevent conflicts

### Migration Conflict Prevention

1. Always check the latest main before creating a new migration file to avoid sequence number collisions
2. If multiple worktrees need new migrations simultaneously, reserve numbers in advance (via issue or coordination)
3. Avoid operations that could corrupt the DB schema during tests

### Integration Tests

- Integration tests share the same database — **do not run them in parallel**
- Unit tests (`make test`) can run independently in each worktree
- Run `make test-integration` from only one worktree at a time

### Docker Management

```bash
# Always manage Docker from the main worktree
cd ~/git/mayu
make docker-up     # Start (shared by all worktrees)
make docker-down   # Stop
```

### Build Artifacts

- `bin/` is per-worktree (already in .gitignore)
- Running `make build` in one worktree does not affect others

## Kiro Session Guidelines

### Starting a Session

Navigate to the worktree directory before starting Kiro:

```bash
cd ~/git/mayu-worktree/feature-api
kiro chat
```

### Context Sharing

- `.kiro/steering/` is part of the repository, so it exists in every worktree automatically
- Communicate worktree-specific context (scope, goals) at the start of each session
- Use descriptive branch names so the work purpose is self-evident

### Branch Strategy

- Create feature branches from main
- After work is complete, push and open a PR to merge into main
- Delete the worktree after the branch is merged

## Common Workflows

### Parallel Feature Development

```bash
# 1. Update main in the primary worktree
cd ~/git/mayu
git pull origin main

# 2. Create worktree
mkdir -p ~/git/mayu-worktree
git worktree add ~/git/mayu-worktree/feature-api -b feature/api-server

# 3. Start Kiro session in the worktree
cd ~/git/mayu-worktree/feature-api
kiro chat

# 4. After work is complete
git push -u origin feature/api-server
gh pr create

# 5. Cleanup after merge
cd ~/git/mayu
git worktree remove ~/git/mayu-worktree/feature-api
git branch -d feature/api-server
```

### Urgent Bug Fix (while another worktree is active)

```bash
# Create fix branch directly from main
cd ~/git/mayu
git worktree add ~/git/mayu-worktree/fix-urgent -b fix/urgent-issue

cd ~/git/mayu-worktree/fix-urgent
kiro chat
# ... fix the issue ...
```
