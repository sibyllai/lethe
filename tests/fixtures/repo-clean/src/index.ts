// Clean TypeScript application - no secrets

interface User {
  id: number;
  name: string;
  email: string;
}

function createUser(name: string, email: string): User {
  return {
    id: Math.floor(Math.random() * 10000),
    name,
    email,
  };
}

function greet(user: User): string {
  return `Hello, ${user.name}! Welcome to our platform.`;
}

const users: User[] = [];

export function addUser(name: string, email: string): User {
  const user = createUser(name, email);
  users.push(user);
  return user;
}

export function getUsers(): User[] {
  return [...users];
}

export function findUserById(id: number): User | undefined {
  return users.find((u) => u.id === id);
}

export { greet };
