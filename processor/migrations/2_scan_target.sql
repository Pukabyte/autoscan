CREATE TABLE IF NOT EXISTS scan_target (
    "folder"    TEXT NOT NULL,
    "target_id" TEXT NOT NULL,
    PRIMARY KEY (folder, target_id)
);
