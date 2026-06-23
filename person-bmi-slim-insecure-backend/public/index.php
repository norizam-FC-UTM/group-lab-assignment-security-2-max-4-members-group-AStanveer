<?php
// ==========================================================
// SECJ3483 Web Technology
// Person BMI Insecure Slim Backend Starter
// ==========================================================
// NOTA:
// This backend is intentionally insecure.
// provided for investigation and fixing during lab activiy this week.
// Do NOT use this code in real applications.
// ==========================================================

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\Factory\AppFactory;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/db.php';

// FIX 5: Secret key used to sign/verify JWTs.
define('JWT_SECRET', (require __DIR__ . '/../src/config.php')['jwt_secret']);

$app = AppFactory::create();

// Required for JSON/form body parsing in Slim 4.
$app->addBodyParsingMiddleware();

// Helpful for development error display.
// INSECURE: In production, detailed errors should not be shown to users.
$app->addErrorMiddleware(true, true, true);

// ----------------------------------------------------------
// CORS for Vue CLI frontend
// ----------------------------------------------------------
$app->add(function (Request $request, $handler) {
    if ($request->getMethod() === 'OPTIONS') {
        $response = new \Slim\Psr7\Response();
    } else {
        $response = $handler->handle($request);
    }

    return $response
        ->withHeader('Access-Control-Allow-Origin', '*') // INSECURE: convenient untuk aktiviti lab, tidak untuk production.
        ->withHeader('Access-Control-Allow-Headers', 'X-Requested-With, Content-Type, Accept, Origin, Authorization')
        ->withHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS')
        ->withHeader('Access-Control-Allow-Credentials', 'false');
});

// ----------------------------------------------------------
// Helper functions
// ----------------------------------------------------------
function jsonResponse(Response $response, $data, int $status = 200): Response
{
    $response->getBody()->write(json_encode($data, JSON_PRETTY_PRINT));

    return $response
        ->withHeader('Content-Type', 'application/json')
        ->withStatus($status);
}

//
function getRequestData(Request $request): array
{
    $data = $request->getParsedBody();

    if (is_array($data) && !empty($data)) {
        return $data;
    }

    $rawBody = (string) $request->getBody();

    if ($rawBody !== '') {
        $jsonData = json_decode($rawBody, true);

        if (is_array($jsonData)) {
            return $jsonData;
        }
    }

    return is_array($data) ? $data : [];
}

// FIX 5: Base64url helpers (JWT uses base64url, not standard base64).
function base64UrlEncode(string $data): string
{
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

function base64UrlDecode(string $data): string
{
    return base64_decode(strtr($data, '-_', '+/'));
}

// FIX 5: Real signed JWT (HMAC-SHA256), hand-rolled with no external library.
// Payload only carries user_id, role, iat, exp - never password, password_hash,
// the secret key, or other private personal data.
function createFakeToken(array $user): string
{
    $header = ['alg' => 'HS256', 'typ' => 'JWT'];
    $payload = [
        'user_id' => $user['id'],
        'role' => $user['role'],
        'iat' => time(),
        'exp' => time() + 3600
    ];

    $headerEncoded = base64UrlEncode(json_encode($header));
    $payloadEncoded = base64UrlEncode(json_encode($payload));

    $signature = hash_hmac('sha256', "$headerEncoded.$payloadEncoded", JWT_SECRET, true);
    $signatureEncoded = base64UrlEncode($signature);

    return "$headerEncoded.$payloadEncoded.$signatureEncoded";
}

// FIX 5: Verify the signature (timing-safe) and expiry before trusting the payload.
function getFakeUserFromToken(Request $request): ?array
{
    $auth = $request->getHeaderLine('Authorization');

    if (!$auth || !preg_match('/Bearer\s+(\S+)/', $auth, $matches)) {
        return null;
    }

    $parts = explode('.', $matches[1]);

    if (count($parts) !== 3) {
        return null;
    }

    [$headerEncoded, $payloadEncoded, $signatureEncoded] = $parts;

    $expectedSignature = hash_hmac('sha256', "$headerEncoded.$payloadEncoded", JWT_SECRET, true);

    if (!hash_equals($expectedSignature, base64UrlDecode($signatureEncoded))) {
        return null;
    }

    $payload = json_decode(base64UrlDecode($payloadEncoded), true);

    if (!is_array($payload) || !isset($payload['exp']) || $payload['exp'] < time()) {
        return null;
    }

    return $payload;
}

function exposeException(Response $response, Throwable $e): Response
{
    // FIX 12: Log details server-side; never expose them to the client.
    error_log($e->getMessage());

    return jsonResponse($response, [
        "error" => "Unable to process request"
    ], 500);
}

// FIX 2: Backend BMI calculation.
function calculateBmi($height, $weight)
{
    return round($weight / ($height * $height), 2);
}

function getBmiCategory($bmi)
{
    if ($bmi < 18.5) {
        return "Underweight";
    } elseif ($bmi < 25) {
        return "Normal";
    } elseif ($bmi < 30) {
        return "Overweight";
    } else {
        return "Obese";
    }
}

// ----------------------------------------------------------
// Root routes
// ----------------------------------------------------------
$app->get('/', function (Request $request, Response $response) {
    return jsonResponse($response, [
        'message' => 'Person BMI Insecure Slim Backend Starter',
        'warning' => 'This backend is intentionally insecure for classroom investigation.'
    ]);
});

$app->get('/api/health', function (Request $request, Response $response) {
    return jsonResponse($response, [
        'status' => 'ok',
        'api' => 'person-bmi-insecure-backend'
    ]);
});

// ----------------------------------------------------------
// Public route: Register
// ----------------------------------------------------------
$app->post('/api/register', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();
        $data = getRequestData($request);

        // INSECURE:
        // - No backend validation.
        // - Role is accepted from frontend, so user can register as admin/staff.
        $name = $data['name'] ?? '';
        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';
        $role = $data['role'] ?? 'user';

        // FIX 3: Hash the password before storing it; plaintext is never saved.
        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        $sql = "INSERT INTO users (name, email, password_hash, role)
                VALUES ('$name', '$email', '$passwordHash', '$role')";

        // INSECURE: direct SQL execution with user input.
        $pdo->exec($sql);
        $id = $pdo->lastInsertId();

        // FIX 10: Only return safe fields, never password/password_hash.
        $stmt = $pdo->prepare("SELECT id, name, email, role FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $user = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'User registered.',
            'user' => $user
        ], 201);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Public route: Login
// ----------------------------------------------------------
$app->post('/api/login', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();
        $data = getRequestData($request);

        $email = $data['email'] ?? '';
        $password = $data['password'] ?? '';

        // FIX 4: Prepared statement prevents SQL Injection via the email field.
        $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();

        // FIX 3: Verify the submitted password against the stored bcrypt hash.
        if (!$user || !password_verify($password, $user['password_hash'])) {
            return jsonResponse($response, [
                'error' => 'Invalid email or password'
            ], 401);
        }

        // INSECURE: fake unsigned token with no expiry.
        $token = createFakeToken($user);

        // FIX 10: Only return safe fields, never password/password_hash.
        $safeUser = [
            'id' => $user['id'],
            'name' => $user['name'],
            'email' => $user['email'],
            'role' => $user['role']
        ];

        return jsonResponse($response, [
            'message' => 'Login successful.',
            'token' => $token,
            'user' => $safeUser
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Protected-ish route: Profile
// ----------------------------------------------------------
$app->get('/api/profile', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $fakeUser = getFakeUserFromToken($request);

        // FIX 6: Reject requests without a valid token.
        if (!$fakeUser) {
            return jsonResponse($response, [
                "error" => "Unauthorized"
            ], 401);
        }

        // INSECURE: trusts unsigned editable token.
        $userId = $fakeUser['user_id'] ?? 1;

        // FIX 10: Only return safe fields, never password/password_hash.
        $stmt = $pdo->prepare("SELECT id, name, email, role FROM users WHERE id = ?");
        $stmt->execute([$userId]);
        $user = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'Profile returned.',
            'user' => $user,
            'token_payload_trusted_by_backend' => $fakeUser
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// BMI routes
// ----------------------------------------------------------
$app->get('/api/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $fakeUser = getFakeUserFromToken($request);

        // FIX 6: Reject requests without a valid token.
        if (!$fakeUser) {
            return jsonResponse($response, [
                "error" => "Unauthorized"
            ], 401);
        }

        // INSECURE: trusts unsigned token; also accepts ?user_id= to override owner.
        $params = $request->getQueryParams();
        $userId = $params['user_id'] ?? ($fakeUser['user_id'] ?? null);

        if ($userId) {
            $sql = "SELECT * FROM persons WHERE user_id = $userId ORDER BY id DESC";
        } else {
            $sql = "SELECT * FROM persons ORDER BY id DESC";
        }

        $persons = $pdo->query($sql)->fetchAll();

        return jsonResponse($response, [
            'message' => 'BMI records returned. This route is intentionally weak.',
            'persons' => $persons,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->post('/api/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();
        $data = getRequestData($request);

        $fakeUser = getFakeUserFromToken($request);

        // FIX 6: Reject requests without a valid token.
        if (!$fakeUser) {
            return jsonResponse($response, [
                "error" => "Unauthorized"
            ], 401);
        }

        // FIX 1: Backend validation for BMI data.
        if (!isset($data['name']) || trim($data['name']) === '') {
            return jsonResponse($response, ["error" => "Name is required"], 400);
        }

        if (!isset($data['age']) || $data['age'] < 1 || $data['age'] > 120) {
            return jsonResponse($response, ["error" => "Age must be between 1 and 120"], 400);
        }

        if (!isset($data['height']) || $data['height'] < 0.5 || $data['height'] > 2.5) {
            return jsonResponse($response, ["error" => "Height must be between 0.5 and 2.5 meters"], 400);
        }

        if (!isset($data['weight']) || $data['weight'] < 2 || $data['weight'] > 300) {
            return jsonResponse($response, ["error" => "Weight must be between 2 and 300 kg"], 400);
        }

        // INSECURE:
        // - Trusts user_id from frontend.
        $user_id = $data['user_id'] ?? 1;
        $name = $data['name'] ?? '';
        $age = $data['age'] ?? 0;
        $height = $data['height'] ?? 0;
        $weight = $data['weight'] ?? 0;
        $notes = $data['notes'] ?? '';

        // FIX 2: bmi and category are calculated at the backend, not trusted from frontend.
        $bmi = calculateBmi($height, $weight);
        $category = getBmiCategory($bmi);

        $sql = "INSERT INTO persons (user_id, name, age, height, weight, bmi, category, notes)
                VALUES ($user_id, '$name', $age, $height, $weight, $bmi, '$category', '$notes')";

        $pdo->exec($sql);
        $id = $pdo->lastInsertId();

        $person = $pdo->query("SELECT * FROM persons WHERE id = $id")->fetch();

        return jsonResponse($response, [
            'message' => 'BMI record created. This route trusts frontend data.',
            'person' => $person,
            'debug_received_body' => $data,
            'debug_sql' => $sql
        ], 201);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->get('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];

        $fakeUser = getFakeUserFromToken($request);

        // FIX 6: Reject requests without a valid token.
        if (!$fakeUser) {
            return jsonResponse($response, [
                "error" => "Unauthorized"
            ], 401);
        }

        $sql = "SELECT * FROM persons WHERE id = $id";
        $person = $pdo->query($sql)->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        // FIX 7: Owner-based access control. Owner, staff, or admin may view.
        $currentUserId = $fakeUser['user_id'];
        $currentUserRole = $fakeUser['role'] ?? 'user';
        $recordOwnerId = $person['user_id'];

        if ($currentUserId != $recordOwnerId && !in_array($currentUserRole, ['staff', 'admin'])) {
            return jsonResponse($response, [
                "error" => "Access denied"
            ], 403);
        }

        return jsonResponse($response, [
            'message' => 'Record returned.',
            'person' => $person,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->put('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];
        $data = getRequestData($request);

        $fakeUser = getFakeUserFromToken($request);

        // FIX 6: Reject requests without a valid token.
        if (!$fakeUser) {
            return jsonResponse($response, [
                "error" => "Unauthorized"
            ], 401);
        }

        $existing = $pdo->query("SELECT * FROM persons WHERE id = $id")->fetch();

        if (!$existing) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        // FIX 7: Owner-based access control. Owner or admin may update; staff may not.
        $currentUserId = $fakeUser['user_id'];
        $currentUserRole = $fakeUser['role'] ?? 'user';
        $recordOwnerId = $existing['user_id'];

        if ($currentUserId != $recordOwnerId && $currentUserRole !== 'admin') {
            return jsonResponse($response, [
                "error" => "Access denied"
            ], 403);
        }

        // FIX 9: Prevent unauthorized field update.
        // Only these fields may be changed by the client; user_id, role, bmi,
        // and category are controlled by the backend and cannot be overwritten.
        $allowedFields = ['name', 'age', 'height', 'weight', 'notes'];
        $cleanData = [];

        foreach ($allowedFields as $field) {
            if (isset($data[$field])) {
                $cleanData[$field] = $data[$field];
            }
        }

        if (!$cleanData) {
            return jsonResponse($response, [
                'error' => 'No fields to update'
            ], 400);
        }

        // FIX 9: bmi and category are recalculated whenever height/weight change.
        $height = $cleanData['height'] ?? $existing['height'];
        $weight = $cleanData['weight'] ?? $existing['weight'];
        $bmi = calculateBmi($height, $weight);
        $category = getBmiCategory($bmi);

        $name = $cleanData['name'] ?? $existing['name'];
        $age = $cleanData['age'] ?? $existing['age'];
        $notes = $cleanData['notes'] ?? $existing['notes'];

        $sql = "UPDATE persons SET
                name = '$name',
                age = $age,
                height = $height,
                weight = $weight,
                bmi = $bmi,
                category = '$category',
                notes = '$notes'
                WHERE id = $id";
        $pdo->exec($sql);

        $person = $pdo->query("SELECT * FROM persons WHERE id = $id")->fetch();

        return jsonResponse($response, [
            'message' => 'BMI record updated securely.',
            'person' => $person
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->delete('/api/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];

        $fakeUser = getFakeUserFromToken($request);

        // FIX 6: Reject requests without a valid token.
        if (!$fakeUser) {
            return jsonResponse($response, [
                "error" => "Unauthorized"
            ], 401);
        }

        $person = $pdo->query("SELECT * FROM persons WHERE id = $id")->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        // FIX 7: Owner-based access control. Owner or admin may delete; staff may not.
        $currentUserId = $fakeUser['user_id'];
        $currentUserRole = $fakeUser['role'] ?? 'user';
        $recordOwnerId = $person['user_id'];

        if ($currentUserId != $recordOwnerId && $currentUserRole !== 'admin') {
            return jsonResponse($response, [
                "error" => "Access denied"
            ], 403);
        }

        $sql = "DELETE FROM persons WHERE id = $id";
        $pdo->exec($sql);

        return jsonResponse($response, [
            'message' => 'BMI record deleted.',
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Staff routes
// ----------------------------------------------------------
$app->get('/api/staff/persons', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $fakeUser = getFakeUserFromToken($request);

        // FIX 6: Reject requests without a valid token.
        if (!$fakeUser) {
            return jsonResponse($response, [
                "error" => "Unauthorized"
            ], 401);
        }

        // FIX 8: Role-based access control. Staff or admin only.
        if (!in_array($fakeUser['role'] ?? 'user', ['staff', 'admin'])) {
            return jsonResponse($response, ["error" => "Staff access required"], 403);
        }

        $sql = "SELECT persons.*, users.email AS owner_email, users.role AS owner_role
                FROM persons
                JOIN users ON persons.user_id = users.id
                ORDER BY persons.id DESC";

        $persons = $pdo->query($sql)->fetchAll();

        return jsonResponse($response, [
            'message' => 'All BMI records returned.',
            'persons' => $persons,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->get('/api/staff/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];

        $fakeUser = getFakeUserFromToken($request);

        // FIX 6: Reject requests without a valid token.
        if (!$fakeUser) {
            return jsonResponse($response, [
                "error" => "Unauthorized"
            ], 401);
        }

        // FIX 8: Role-based access control. Staff or admin only.
        if (!in_array($fakeUser['role'] ?? 'user', ['staff', 'admin'])) {
            return jsonResponse($response, ["error" => "Staff access required"], 403);
        }

        $sql = "SELECT persons.*, users.email AS owner_email, users.role AS owner_role
                FROM persons
                JOIN users ON persons.user_id = users.id
                WHERE persons.id = $id";

        $person = $pdo->query($sql)->fetch();

        if (!$person) {
            return jsonResponse($response, ['error' => 'Record not found'], 404);
        }

        return jsonResponse($response, [
            'message' => 'Staff record returned without role check.',
            'person' => $person,
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// ----------------------------------------------------------
// Admin routes
// ----------------------------------------------------------
$app->get('/api/admin/users', function (Request $request, Response $response) {
    try {
        $pdo = getPDO();

        $fakeUser = getFakeUserFromToken($request);

        // FIX 6: Reject requests without a valid token.
        if (!$fakeUser) {
            return jsonResponse($response, [
                "error" => "Unauthorized"
            ], 401);
        }

        // FIX 8: Role-based access control. Admin only.
        if (($fakeUser['role'] ?? 'user') !== 'admin') {
            return jsonResponse($response, ["error" => "Admin access required"], 403);
        }

        // FIX 10: Only return safe fields, never password/password_hash.
        $sql = "SELECT id, name, email, role, created_at FROM users ORDER BY id ASC";
        $users = $pdo->query($sql)->fetchAll();

        return jsonResponse($response, [
            'message' => 'All users returned.',
            'users' => $users
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->put('/api/admin/users/{id}/role', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];
        $data = getRequestData($request);
        $role = $data['role'] ?? 'user';

        $fakeUser = getFakeUserFromToken($request);

        // FIX 6: Reject requests without a valid token.
        if (!$fakeUser) {
            return jsonResponse($response, [
                "error" => "Unauthorized"
            ], 401);
        }

        // FIX 8: Role-based access control. Admin only.
        if (($fakeUser['role'] ?? 'user') !== 'admin') {
            return jsonResponse($response, ["error" => "Admin access required"], 403);
        }

        $sql = "UPDATE users SET role = '$role' WHERE id = $id";
        $pdo->exec($sql);

        // FIX 10: Only return safe fields, never password/password_hash.
        $stmt = $pdo->prepare("SELECT id, name, email, role FROM users WHERE id = ?");
        $stmt->execute([$id]);
        $user = $stmt->fetch();

        return jsonResponse($response, [
            'message' => 'User role updated.',
            'user' => $user
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

$app->delete('/api/admin/persons/{id}', function (Request $request, Response $response, array $args) {
    try {
        $pdo = getPDO();
        $id = $args['id'];

        $fakeUser = getFakeUserFromToken($request);

        // FIX 6: Reject requests without a valid token.
        if (!$fakeUser) {
            return jsonResponse($response, [
                "error" => "Unauthorized"
            ], 401);
        }

        // FIX 8: Role-based access control. Admin only.
        if (($fakeUser['role'] ?? 'user') !== 'admin') {
            return jsonResponse($response, ["error" => "Admin access required"], 403);
        }

        $sql = "DELETE FROM persons WHERE id = $id";
        $pdo->exec($sql);

        return jsonResponse($response, [
            'message' => 'Admin delete executed without admin role verification.',
            'debug_sql' => $sql
        ]);
    } catch (Throwable $e) {
        return exposeException($response, $e);
    }
});

// Preflight catch-all
$app->options('/{routes:.+}', function (Request $request, Response $response) {
    return $response;
});

$app->run();
