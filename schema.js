Project {
  name: "COMP101 Quests"
  database_type: "PostgreSQL"
}

// ===== Enums =====
Enum role {
  STUDENT
  MENTOR
  ADMIN
}

Enum task_type {
  CODE
  MCQ
  TEXT
  REFLECTION
  VISIT        // visit a URL / watch a video
  FILE_UPLOAD
}

Enum testcase_visibility {
  SAMPLE
  HIDDEN
}

Enum submission_status {
  PENDING
  PASSED
  FAILED
  PARTIAL
  ERROR
}

// ===== Core people & grouping =====
Table users {
  id bigserial [pk]
  name text
  email text [not null, unique]
  role role [not null, default: 'STUDENT']
  created_at timestamptz [not null, default: `now()`]
}

Table cohorts {
  id bigserial [pk]
  name text [not null]
  term text
  year int
}

Table enrollments {
  user_id bigint [not null, ref: > users.id]
  cohort_id bigint [not null, ref: > cohorts.id]
  role_in_cohort role [not null, default: 'STUDENT']
  joined_at timestamptz [not null, default: `now()`]

  Note: "Composite PK ensures uniqueness per cohort"
  Indexes {
    (user_id, cohort_id) [pk]
  }
}

// ===== Learning outcomes, quests, tasks =====
Table learning_outcomes {
  id bigserial [pk]
  code text [not null, unique] // e.g., LO1, LO2...
  title text [not null]
  description text
}

Table quests {
  id bigserial [pk]
  code text [not null, unique]
  title text [not null]
  description text
  xp int [not null, default: 10]
  difficulty int // 1..5
  is_optional boolean [not null, default: false]
  published boolean [not null, default: false]
  starts_at timestamptz
  due_at timestamptz
}

Table quest_outcomes {
  quest_id bigint [not null, ref: > quests.id]
  lo_id bigint [not null, ref: > learning_outcomes.id]
  weight int [not null, default: 1]

  Indexes {
    (quest_id, lo_id) [pk]
  }
}

// Gating: quest prerequisites
Table quest_prereq {
  quest_id bigint [not null, ref: > quests.id]
  prereq_quest_id bigint [not null, ref: > quests.id]

  Indexes {
    (quest_id, prereq_quest_id) [pk]
  }
}

Table tasks {
  id bigserial [pk]
  quest_id bigint [not null, ref: > quests.id]
  slug text [not null]
  title text [not null]
  description text
  type task_type [not null]
  points int [not null, default: 1]
  order_in_quest int [not null, default: 1] // rendering + progression order
  must_pass boolean [not null, default: true]
  min_score_to_pass numeric(5,2) [not null, default: 1.00] // 0..points

  Indexes {
    (quest_id, order_in_quest) name: "idx_tasks_quest_order"
    (quest_id, slug) [unique]
  }
}

// Gating: task prerequisites (within or across quests if desired)
Table task_prereq {
  task_id bigint [not null, ref: > tasks.id]
  prereq_task_id bigint [not null, ref: > tasks.id]

  Indexes {
    (task_id, prereq_task_id) [pk]
  }
}

Table task_resources {
  id bigserial [pk]
  task_id bigint [not null, ref: > tasks.id]
  label text
  url text
  kind text // 'video', 'doc', 'link', 'dataset', ...
}

// For CODE/MCQ/TEXT autograding
Table task_testcases {
  id bigserial [pk]
  task_id bigint [not null, ref: > tasks.id]
  name text
  input text
  expected_output text
  visibility testcase_visibility [not null, default: 'HIDDEN']
  weight numeric(5,2) [not null, default: 1.00]
  timeout_ms int
  memory_limit_mb int
}

// ===== Submissions & grading =====
Table submissions {
  id bigserial [pk]
  task_id bigint [not null, ref: > tasks.id]
  user_id bigint [not null, ref: > users.id]
  created_at timestamptz [not null, default: `now()`]
  status submission_status [not null, default: 'PENDING']
  score numeric(6,2) [not null, default: 0.00]
  feedback text

  Indexes {
    (task_id, user_id, created_at) name: "idx_submissions_lookup"
  }
}

Table submission_artifacts {
  id bigserial [pk]
  submission_id bigint [not null, ref: > submissions.id]
  kind text // 'code', 'text', 'json', 'file_url'
  filename text
  content text // store inline small payloads; large files via URL
}

// Optional roll-up per quest (cached/derived)
Table quest_grades {
  id bigserial [pk]
  quest_id bigint [not null, ref: > quests.id]
  user_id bigint [not null, ref: > users.id]
  best_score numeric(6,2) [not null, default: 0.00]
  passed boolean [not null, default: false]
  last_updated timestamptz [not null, default: `now()`]

  Indexes {
    (quest_id, user_id) [unique]
  }
}

