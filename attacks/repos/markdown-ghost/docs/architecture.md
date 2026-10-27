# Architecture

The writer appends to a per-note journal, then folds the journal into
the Markdown file on flush. The reader only sees folded files, so a
crash mid-write never exposes a half-written note.
