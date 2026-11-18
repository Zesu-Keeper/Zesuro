/** An error that is safe to show to the caller, with its HTTP status. */
export class EntryError extends Error {
  constructor(
    message: string,
    public status = 400,
  ) {
    super(message);
  }
}
