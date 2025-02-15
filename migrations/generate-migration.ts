import { Migration } from "./migration";
import * as fs from "fs";
import * as path from "path";

function main() {
  const migrationName = process.argv[2] || "";

  try {
    const migration = new Migration(migrationName);
    const migrationId = migration.generateId();

    // Create the SQL file
    const sqlFileName = `${migrationId}.sql`;
    const sqlFilePath = path.join(__dirname, sqlFileName);
    fs.writeFileSync(sqlFilePath, "");

    console.log(`Migration ID: ${migrationId}`);
    console.log(`SQL file created: ${sqlFilePath}`);
  } catch (error) {
    console.error("Error:", (error as Error).message);
    process.exit(1);
  }
}

main();
