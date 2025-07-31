#include <iostream>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <cstring>
#include <sstream>
#pragma warning(disable:4996)

using namespace std;

// Структура для хранения информации о подключённом пользователе
struct UserInfo {
	int id;         // Уникальный идентификатор пользователя (id потока)
	SOCKET socket;  // Сокет пользователя
};

// Глобальный список всех подключённых пользователей
vector<UserInfo> Users_Connected;

mutex mtx;         // Мьютекс для синхронизации доступа к Users_Connected
int counter = 0;   // Счётчик подключённых пользователей

// Функция для получения строки от клиента (сначала размер, потом само сообщение)
string recv(SOCKET client) {
	int msg_size_recv = 0;
	recv(client, (char*)&msg_size_recv, sizeof(int), NULL);
	char* msg_recv = new char[msg_size_recv + 1];
	recv(client, msg_recv, msg_size_recv, NULL);
	msg_recv[msg_size_recv] = '\0';
	string receivedPassword(msg_recv);
	delete[] msg_recv;
	return receivedPassword;
}

// Функция для отправки строки клиенту (сначала размер, потом само сообщение)
void send(SOCKET client, string msg) {
	size_t msg_size_send = msg.size();
	send(client, (char*)&msg_size_send, sizeof(int), NULL);
	send(client, msg.c_str(), msg_size_send, NULL);
}

// Функция аутентификации пользователя по паролю
bool RecvPassword(SOCKET client) {
	const int maxAttempts = 4;

	// Получаем id потока для идентификации пользователя
	stringstream ss;
	ss << this_thread::get_id();
	int id;
	ss >> id;
	string id_client = to_string(id);

	// Приветственное сообщение и запрос пароля
	string msg = "Hello, to enter the chat enter the password: ";
	send(client, msg);
	for (int current = 1; current != maxAttempts; ++current) {
		if (recv(client) == "ban") {
			send(client, "Password true! You have access to chat.");
			send(client, "You have been assigned an id: " + id_client);
			return true;
		}
		else {
			if (current <= maxAttempts) {
				int attempt_left = maxAttempts - current;
				string msg_attempt = to_string(attempt_left) + " attempt(s) left. Try again: ";
				send(client, msg_attempt);
			}
		}
	}
	send(client, "All attempts are wasted.");
	return false;
}

// Функция для кика пользователя по id (отправляет сообщение и закрывает соединение)
void KickUser(int id) {
	mtx.lock();
	for (auto it = Users_Connected.begin(); it != Users_Connected.end(); ++it) {
		if (it->id == id) {
			send(it->socket, "You have been kicked from the server.");
			closesocket(it->socket);
			Users_Connected.erase(it);
			counter--;
			cout << "User with id " << id << " has been kicked." << endl;
			mtx.unlock();
			return;
		}
	}
	mtx.unlock();
	cout << "User with id " << id << " not found." << endl;
}

// Функция-обработчик для каждого клиента (работает в отдельном потоке)
void ClientHandler(SOCKET clientsocket) {
	// Получаем id потока для идентификации пользователя
	stringstream ss;
	ss << this_thread::get_id();
	int id;
	ss >> id;
	string id_client = to_string(id);

	// Аутентификация пользователя
	if (!RecvPassword(clientsocket)) {
		cout << "Authentication failed for " << id_client << ". Closing connection." << endl;
		closesocket(clientsocket);
		return;
	}

	cout << "User " << id_client << " successfully authenticated." << endl;

	// Добавляем пользователя в общий список
	mtx.lock();
	Users_Connected.push_back({ id, clientsocket });
	counter++;
	mtx.unlock();

	// Основной цикл приёма и рассылки сообщений
	while (true) {
		int msg_size = 0;
		int result = recv(clientsocket, (char*)&msg_size, sizeof(int), NULL); // Приём размера сообщения
		if (result <= 0) {
			cout << "User " << id_client << " disconected or error." << endl;
			mtx.lock();
			for (auto it = Users_Connected.begin(); it != Users_Connected.end(); ++it) {
				if (it->socket == clientsocket) {
					Users_Connected.erase(it);
					break;
				}
			}
			counter--;
			mtx.unlock();
			closesocket(clientsocket);
			break;
		}
		char* msg = new char[msg_size + 1]; // Выделение памяти под сообщение
		msg[msg_size] = '\0'; // Для конца строки
		result = recv(clientsocket, msg, msg_size, NULL); // Приём самого сообщения 
		if (result <= 0) {
			cout << "User " << id_client << " disconected or error." << endl;
			mtx.lock();
			for (auto it = Users_Connected.begin(); it != Users_Connected.end(); ++it) {
				if (it->socket == clientsocket) {
					Users_Connected.erase(it);
					break;
				}
			}
			counter--;
			mtx.unlock();
			closesocket(clientsocket);
			delete[] msg;
			break;
		}
		// Рассылка сообщения всем остальным пользователям
		mtx.lock();
		for (const auto& user : Users_Connected) {
			if (user.socket == clientsocket) continue;
			if (user.socket == INVALID_SOCKET) continue;
			send(user.socket, id_client + ":");
			send(user.socket, (char*)&msg_size, sizeof(int), NULL); // Отправка размера сообщения
			send(user.socket, msg, msg_size, NULL); // Отправка сообщения
		}
		mtx.unlock();
		delete[] msg;
	}
}

// Главная функция: инициализация сервера, приём подключений и запуск потоков
int main() {
	WSAData wsadata;
	WORD WinSockVer = MAKEWORD(2, 2);

	// Инициализация WinSock
	if (WSAStartup(WinSockVer, &wsadata) != 0) {
		cout << "Error" << endl;
		exit(1);
	}

	// Настройка адреса сервера
	SOCKADDR_IN addr;
	int size_of_len = sizeof(addr);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // Сервер слушает только локальные подключения
	addr.sin_port = htons(4444);
	addr.sin_family = AF_INET;

	// Создание и запуск серверного сокета
	SOCKET slisten = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (bind(slisten, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
		cout << "Bind ERROR." << endl;
	if (listen(slisten, SOMAXCONN) == SOCKET_ERROR)
		cout << "Listen ERROR." << endl;
	cout << "Server start listen client..." << endl;

	SOCKET newconnection;
	vector<thread> client_threads;

	// Отдельный поток для обработки команд с консоли (например, /kick <id>)
	thread([]() {
		string command;
		while (true) {
			getline(cin, command);
			if (command.find("/kick") == 0) {
				stringstream ss(command);
				string cmd;
				int id;
				ss >> cmd >> id;
				KickUser(id);
			}
			else {
				cout << "Unknown command. Use /kick <id> to kick a user." << endl;
			}
		}
		}).detach();

	// Основной цикл: приём новых подключений и запуск потоков для клиентов
	while (true) {
		newconnection = accept(slisten, (SOCKADDR*)&addr, &size_of_len);

		if (newconnection == INVALID_SOCKET)
			cout << "User is not connected." << endl;
		else {
			cout << "New User attempting to connect." << endl;
			client_threads.emplace_back(ClientHandler, newconnection);
			client_threads.back().detach();
		}
	}

	// Завершение работы сервера
	WaitForMultipleObjects(counter, NULL, TRUE, INFINITY);
	closesocket(slisten);
	WSACleanup();

	return 0;
}