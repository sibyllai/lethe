// Application configuration

const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

const DATABASE_URL = "postgresql://admin:supersecretpassword123@db.example.com:5432/myapp";

const API_KEY = "sk_test_FAKEFAKEFAKEFAKE1234567890";

export const config = {
  port: 3000,
  host: "localhost",
  aws: {
    accessKeyId: AWS_ACCESS_KEY_ID,
    secretAccessKey: AWS_SECRET_ACCESS_KEY,
  },
  database: DATABASE_URL,
  apiKey: API_KEY,
};
