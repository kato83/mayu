import { Component, inject, signal, OnInit, viewChild } from '@angular/core';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { FormsModule } from '@angular/forms';

import { TeamService } from '../../services/team.service';
import { AuthService } from '../../services/auth.service';
import { Team, TeamMember, TeamDashboardSummary, UserInfo } from '../../models/team.model';
import { ConfirmDialogComponent } from '../../shared/confirm-dialog/confirm-dialog.component';

@Component({
  selector: 'app-team-detail',
  standalone: true,
  imports: [FormsModule, RouterLink, ConfirmDialogComponent],
  template: `
    <div class="p-6">
      <!-- Back link -->
      <a routerLink="/teams" class="text-sm text-blue-600 dark:text-blue-400 hover:underline mb-4 inline-block" i18n="@@teamDetail.backToTeams">
        ← Back to Teams
      </a>

      @if (loading()) {
        <p class="text-slate-500 dark:text-slate-400" i18n="@@teamDetail.loading">Loading...</p>
      } @else if (team()) {
        <!-- Team header -->
        <div class="flex items-center justify-between mb-6">
          <div>
            <h1 class="text-2xl font-bold text-slate-900 dark:text-white">{{ team()!.name }}</h1>
            @if (team()!.description) {
              <p class="mt-1 text-slate-600 dark:text-slate-400">{{ team()!.description }}</p>
            }
          </div>
          <button
            (click)="onDeleteTeam()"
            class="px-3 py-2 text-sm bg-red-600 hover:bg-red-700 text-white rounded-md transition-colors cursor-pointer"
            i18n="@@teamDetail.deleteButton"
          >
            Delete Team
          </button>
        </div>

        <!-- Team Dashboard Summary -->
        @if (dashboard()) {
          <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div class="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg">
              <p class="text-sm text-slate-500 dark:text-slate-400" i18n="@@teamDetail.projects">Projects</p>
              <p class="text-2xl font-bold text-slate-900 dark:text-white">{{ dashboard()!.total_projects }}</p>
            </div>
            <div class="p-4 bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg">
              <p class="text-sm text-slate-500 dark:text-slate-400" i18n="@@teamDetail.findings">Findings</p>
              <p class="text-2xl font-bold text-slate-900 dark:text-white">{{ dashboard()!.total_findings }}</p>
            </div>
            <div class="p-4 bg-white dark:bg-slate-800 border border-red-200 dark:border-red-900 rounded-lg">
              <p class="text-sm text-red-600 dark:text-red-400" i18n="@@teamDetail.critical">Critical</p>
              <p class="text-2xl font-bold text-red-600 dark:text-red-400">{{ dashboard()!.by_severity.critical }}</p>
            </div>
            <div class="p-4 bg-white dark:bg-slate-800 border border-orange-200 dark:border-orange-900 rounded-lg">
              <p class="text-sm text-orange-600 dark:text-orange-400" i18n="@@teamDetail.high">High</p>
              <p class="text-2xl font-bold text-orange-600 dark:text-orange-400">{{ dashboard()!.by_severity.high }}</p>
            </div>
          </div>
        }

        <!-- Members section -->
        <div class="mb-6">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-xl font-semibold text-slate-900 dark:text-white" i18n="@@teamDetail.membersTitle">
              Members
            </h2>
            <button
              (click)="showAddMember.set(true)"
              class="px-3 py-1.5 text-sm bg-blue-600 hover:bg-blue-700 text-white rounded-md transition-colors cursor-pointer"
              i18n="@@teamDetail.addMemberButton"
            >
              Add Member
            </button>
          </div>

          <!-- Add member form -->
          @if (showAddMember()) {
            <div class="mb-4 p-4 bg-slate-50 dark:bg-slate-800 border border-slate-200 dark:border-slate-700 rounded-lg">
              <form (ngSubmit)="onAddMember()" class="flex items-end gap-3 flex-wrap">
                <div class="flex-1 min-w-[200px]">
                  <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@teamDetail.userLabel">
                    User
                  </label>
                  <input
                    type="text"
                    [(ngModel)]="addMemberSearch"
                    name="userSearch"
                    required
                    list="userList"
                    (input)="onUserSearchInput()"
                    class="w-full px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="Search by email or name..."
                    i18n-placeholder="@@teamDetail.userSearchPlaceholder"
                  />
                  <datalist id="userList">
                    @for (u of availableUsers(); track u.id) {
                      <option [value]="u.email">{{ u.name ? u.name + ' (' + u.email + ')' : u.email }}</option>
                    }
                  </datalist>
                </div>
                <div>
                  <label class="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1" i18n="@@teamDetail.roleLabel">
                    Role
                  </label>
                  <select
                    [(ngModel)]="addMemberRole"
                    name="role"
                    class="px-3 py-2 border border-slate-300 dark:border-slate-600 rounded-md bg-white dark:bg-slate-700 text-slate-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  >
                    <option value="member" i18n="@@teamDetail.roleMember">Member</option>
                    <option value="owner" i18n="@@teamDetail.roleOwner">Owner</option>
                  </select>
                </div>
                <button
                  type="submit"
                  [disabled]="!selectedUserId()"
                  class="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-medium rounded-md transition-colors cursor-pointer"
                  i18n="@@teamDetail.addButton"
                >
                  Add
                </button>
                <button
                  type="button"
                  (click)="showAddMember.set(false)"
                  class="px-4 py-2 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-300 font-medium rounded-md transition-colors cursor-pointer"
                  i18n="@@teamDetail.cancelButton"
                >
                  Cancel
                </button>
              </form>
            </div>
          }

          <!-- Members table -->
          @if (members().length === 0) {
            <p class="text-slate-500 dark:text-slate-400" i18n="@@teamDetail.noMembers">No members yet.</p>
          } @else {
            <div class="overflow-x-auto">
              <table class="w-full text-sm text-left">
                <thead class="text-xs text-slate-500 dark:text-slate-400 uppercase bg-slate-50 dark:bg-slate-800 border-b border-slate-200 dark:border-slate-700">
                  <tr>
                    <th class="px-4 py-3" i18n="@@teamDetail.colEmail">Email</th>
                    <th class="px-4 py-3" i18n="@@teamDetail.colName">Name</th>
                    <th class="px-4 py-3" i18n="@@teamDetail.colRole">Role</th>
                    <th class="px-4 py-3" i18n="@@teamDetail.colActions">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  @for (member of members(); track member.id) {
                    <tr class="border-b border-slate-200 dark:border-slate-700">
                      <td class="px-4 py-3 text-slate-900 dark:text-white">{{ member.email }}</td>
                      <td class="px-4 py-3 text-slate-600 dark:text-slate-400">{{ member.name || '-' }}</td>
                      <td class="px-4 py-3">
                        <span
                          class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium"
                          [class]="member.role === 'owner' ? 'bg-amber-100 dark:bg-amber-900/30 text-amber-800 dark:text-amber-300' : 'bg-blue-100 dark:bg-blue-900/30 text-blue-800 dark:text-blue-300'"
                        >
                          {{ member.role }}
                        </span>
                      </td>
                      <td class="px-4 py-3">
                        @if (member.user_id === authService.currentUser()?.id) {
                          <button
                            (click)="onLeaveTeam()"
                            class="text-orange-600 dark:text-orange-400 hover:underline text-xs cursor-pointer"
                            i18n="@@teamDetail.leaveButton"
                          >
                            Leave
                          </button>
                        } @else {
                          <button
                            (click)="onRemoveMember(member.user_id)"
                            class="text-red-600 dark:text-red-400 hover:underline text-xs cursor-pointer"
                            i18n="@@teamDetail.removeButton"
                          >
                            Remove
                          </button>
                        }
                      </td>
                    </tr>
                  }
                </tbody>
              </table>
            </div>
          }
        </div>
      }

      <!-- Error -->
      @if (error()) {
        <p class="mt-4 text-sm text-red-600 dark:text-red-400">{{ error() }}</p>
      }

      <app-confirm-dialog #confirmDialog />
    </div>
  `,
})
export class TeamDetailComponent implements OnInit {
  private readonly route = inject(ActivatedRoute);
  private readonly router = inject(Router);
  private readonly teamService = inject(TeamService);
  readonly authService = inject(AuthService);

  private readonly confirmDialog = viewChild.required(ConfirmDialogComponent);

  team = signal<Team | null>(null);
  members = signal<TeamMember[]>([]);
  dashboard = signal<TeamDashboardSummary | null>(null);
  loading = signal(true);
  error = signal('');
  showAddMember = signal(false);
  addMemberSearch = signal('');
  addMemberRole = signal('member');
  availableUsers = signal<UserInfo[]>([]);
  selectedUserId = signal<number | null>(null);

  private teamId = 0;
  private allUsers: UserInfo[] = [];

  ngOnInit(): void {
    this.teamId = Number(this.route.snapshot.paramMap.get('id'));
    this.loadTeam();
    this.loadMembers();
    this.loadDashboard();
    this.loadUsers();
  }

  loadTeam(): void {
    this.teamService.get(this.teamId).subscribe({
      next: (t) => {
        this.team.set(t);
        this.loading.set(false);
      },
      error: (err) => {
        this.error.set(err?.error?.error || 'Failed to load team');
        this.loading.set(false);
      },
    });
  }

  loadMembers(): void {
    this.teamService.listMembers(this.teamId).subscribe({
      next: (m) => this.members.set(m),
      error: () => {},
    });
  }

  loadDashboard(): void {
    this.teamService.getTeamDashboard(this.teamId).subscribe({
      next: (d) => this.dashboard.set(d),
      error: () => {}, // non-critical
    });
  }

  loadUsers(): void {
    this.teamService.listUsers().subscribe({
      next: (users) => {
        // Exclude current user from candidate list
        const currentUserId = this.authService.currentUser()?.id;
        this.allUsers = currentUserId ? users.filter((u) => u.id !== currentUserId) : users;
        this.availableUsers.set(this.allUsers);
      },
      error: () => {},
    });
  }

  onUserSearchInput(): void {
    const search = this.addMemberSearch().trim().toLowerCase();
    // Try to match exact email to resolve user ID
    const match = this.allUsers.find((u) => u.email.toLowerCase() === search);
    this.selectedUserId.set(match ? match.id : null);

    // Filter available users for datalist (already excludes self)
    if (search) {
      this.availableUsers.set(
        this.allUsers.filter(
          (u) =>
            u.email.toLowerCase().includes(search) ||
            (u.name && u.name.toLowerCase().includes(search)),
        ),
      );
    } else {
      this.availableUsers.set(this.allUsers);
    }
  }

  onAddMember(): void {
    const userId = this.selectedUserId();
    if (!userId) return;

    this.teamService.addMember(this.teamId, { user_id: userId, role: this.addMemberRole() }).subscribe({
      next: () => {
        this.showAddMember.set(false);
        this.addMemberSearch.set('');
        this.selectedUserId.set(null);
        this.addMemberRole.set('member');
        this.loadMembers();
      },
      error: (err) => {
        this.error.set(err?.error?.error || 'Failed to add member');
      },
    });
  }

  async onRemoveMember(userId: number): Promise<void> {
    const confirmed = await this.confirmDialog().open({
      title: $localize`:@@teamDetail.confirmRemoveTitle:Remove Member`,
      message: $localize`:@@teamDetail.confirmRemove:Remove this member from the team?`,
      confirmLabel: $localize`:@@teamDetail.confirmRemoveAction:Remove`,
      destructive: true,
    });
    if (!confirmed) return;

    this.teamService.removeMember(this.teamId, userId).subscribe({
      next: () => this.loadMembers(),
      error: (err) => {
        this.error.set(err?.error?.error || 'Failed to remove member');
      },
    });
  }

  async onLeaveTeam(): Promise<void> {
    const confirmed = await this.confirmDialog().open({
      title: $localize`:@@teamDetail.confirmLeaveTitle:Leave Team`,
      message: $localize`:@@teamDetail.confirmLeave:Are you sure you want to leave this team?`,
      confirmLabel: $localize`:@@teamDetail.confirmLeaveAction:Leave`,
      destructive: true,
    });
    if (!confirmed) return;

    const currentUserId = this.authService.currentUser()?.id;
    if (!currentUserId) return;

    this.teamService.removeMember(this.teamId, currentUserId).subscribe({
      next: () => this.router.navigate(['/teams']),
      error: (err) => {
        this.error.set(err?.error?.error || 'Failed to leave team');
      },
    });
  }

  async onDeleteTeam(): Promise<void> {
    const confirmed = await this.confirmDialog().open({
      title: $localize`:@@teamDetail.confirmDeleteTitle:Delete Team`,
      message: $localize`:@@teamDetail.confirmDelete:Are you sure you want to delete this team?`,
      confirmLabel: $localize`:@@teamDetail.confirmDeleteAction:Delete`,
      destructive: true,
    });
    if (!confirmed) return;

    this.teamService.delete(this.teamId).subscribe({
      next: () => this.router.navigate(['/teams']),
      error: (err) => {
        this.error.set(err?.error?.error || 'Failed to delete team');
      },
    });
  }
}
