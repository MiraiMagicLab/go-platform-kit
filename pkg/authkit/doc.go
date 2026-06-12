// Package authkit là API nhúng chính của go-auth-lib: Gin + Postgres (+ Redis tuỳ chọn) cho auth/RBAC/MFA/OAuth/email.
//
// # Cấu trúc module (chuẩn thư viện Go)
//
// Đường dẫn public — consumer được phép import, giữ tương thích semver:
//
//	github.com/MiraiMagicLab/go-platform-kit/v2/pkg/authkit   — New, Mount*, middleware
//	github.com/MiraiMagicLab/go-platform-kit/v2/pkg/response  — envelope JSON Success / Fail / FailCode (dùng chung với host app)
//	github.com/MiraiMagicLab/go-platform-kit/v2/pkg/token     — JWT (khi host cần tách lẻ)
//
// internal/ — implementation, không import từ repo ngoài module:
//
//	internal/controllers    — HTTP handlers Gin (tương đương controllers trong plugNmeet-server/pkg)
//	internal/middleware     — JWT, RBAC, rate limit, observability
//	internal/services       — nghiệp vụ
//	internal/repositories/postgres — truy cập DB
//	internal/db, internal/config, internal/models, internal/security
//
// Schema & ví dụ:
//
//	sql/, migrations/       — SQL
//	examples/embedded       — mẫu nhúng tối thiểu
//
// Tích hợp thông báo / hàng đợi: gán Config.Hooks.AfterSessionIssued (chạy trong goroutine, không block response).
package authkit
