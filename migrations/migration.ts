/**
 * Class representing a database migration with utility methods for
 * naming and ID generation.
 */
export class Migration {
  constructor(private readonly name: string) {
    this.validateMigrationName(name);
  }

  /**
   * Validates migration name format:
   * - Must start and end with letter/number
   * - Must contain at least one lowercase letter
   * - Can only use lowercase letters, numbers, underscores
   */
  private validateMigrationName(name: string): void {
    const validMigrationNamePattern = /^[a-z0-9](?=.*[a-z])[a-z0-9_]*[a-z0-9]$/;

    if (!validMigrationNamePattern.test(name)) {
      throw new Error(
        "Invalid migration name. Must use lowercase letters, numbers, underscores and " +
          "contain at least one letter. Example: 'create_users_table'"
      );
    }
  }

  /**
   * Gets the validated name of the migration
   */
  getName(): string {
    return this.name;
  }

  /**
   * Generates a migration ID using current timestamp
   */
  generateId(): string {
    const timestamp = Date.now().toString();
    return `${timestamp}_${this.name}`;
  }
}
