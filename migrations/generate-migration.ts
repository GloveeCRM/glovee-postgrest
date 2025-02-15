import { Migration } from "./migration";

function main() {
  const migrationName = process.argv[2] || "";

  try {
    const migration = new Migration(migrationName);
    const migrationId = migration.generateId();
    console.log(migrationId);
  } catch (error) {
    console.error("Error:", (error as Error).message);
    process.exit(1);
  }
}

main();
