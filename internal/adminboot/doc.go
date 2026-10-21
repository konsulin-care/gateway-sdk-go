// Package adminboot performs the minimal admin bootstrap the conformance
// runner needs for setup: admin login, party creation, enrollment tokens, and
// capability grants. It stays internal and is never part of the public client
// (PRD §5: no admin routes in the public surface).
//
// Allowed imports: standard library, wire (PRD §7 dependency rules).
//
// Requirement IDs: SDK-CONF-001.
package adminboot
