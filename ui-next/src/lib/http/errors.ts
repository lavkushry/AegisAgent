export class GatewayRequestError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "GatewayRequestError";
    this.status = status;
  }
}

export class TenantRequiredError extends Error {
  constructor() {
    super("A tenant must be selected before calling the AegisAgent gateway.");
    this.name = "TenantRequiredError";
  }
}
