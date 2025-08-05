#include <iostream>
#include <WinSock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <cstring>
#include <sstream>
#include <windows.h>
#pragma warning(disable:4996)

using namespace std;

const uint64_t p = 3557;
const uint64_t q = 2579;
const uint64_t n = p * q; //Public key modulus

const uint64_t phi = (p - 1) * (q - 1);
const uint64_t e = 17; // Public exponent
static uint64_t modInverse(uint64_t a, uint64_t m) {
	uint64_t m0 = m;
	uint64_t y = 0, x = 1;
	if (m == 1) return 0;
	while (a > 1) {
		uint64_t q = a / m;
		uint64_t t = m;
		m = a % m, a = t;
		t = y;
		y = x - q * y;
		x = t;
	}
	if (x < 0) x += m0;
	return x;
}
const uint64_t d = modInverse(e, phi);

static void index(int i) { cout << i << endl; }

static uint64_t power(uint64_t base, uint64_t exponent, uint64_t modulus) {
	if (modulus == 1) return 0;
	uint64_t result = 1;
	base = base % modulus;
	while (exponent > 0) {
		if (exponent & 1)
			result = (result * base) % modulus;
		base = (base * base) % modulus;
		exponent >>= 1;
	}
	return result;
}

static vector<uint64_t> Encrypting_Message(string msg);
static string Decrypting_Message(const vector<uint64_t>& enc_msg);
static char decrypt(uint64_t x, int volume);
static uint64_t encrypt(unsigned char x, int volume);


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
vector<uint64_t> recv(SOCKET client) {
	int enc_msg_size_recv = 0;
	recv(client, (char*)&enc_msg_size_recv, sizeof(int), NULL);// получение размера сообщения
	if (enc_msg_size_recv <= 0) {
		return {}; // Возвращаем пустой вектор в случае ошибки или пустого сообщения
	}
	vector<uint64_t> enc_msg(enc_msg_size_recv);//устанавливаем ветор с размером полученного сообщения
	recv(client, reinterpret_cast<char*>(enc_msg.data()), enc_msg_size_recv * sizeof(uint64_t), NULL);// принятие самого сообщения
	return enc_msg; //возвращение вектора сообщения зашифрованного
}

// Функция для отправки строки клиенту (сначала размер, потом само сообщение)
void send(SOCKET client, const vector<uint64_t>& enc_msg) {
	size_t enc_msg_size_send = enc_msg.size();// размер сообщения
	send(client, (char*)&enc_msg_size_send, sizeof(int), NULL);//отправка размера
	if (enc_msg_size_send > 0) {
		send(client, reinterpret_cast<const char*>(enc_msg.data()), enc_msg_size_send * sizeof(uint64_t), NULL);//отправка сообщения
	}
}

string recv_string(SOCKET client) {
	auto enc_data = recv(client);//получение ветора сообщения
	if (enc_data.empty()) return "";
	return Decrypting_Message(enc_data); // дешифруем его
}
void send_string(SOCKET client, const string& msg) {
	auto enc_data = Encrypting_Message(msg);//шифруем сообщение
	send(client, enc_data);//отправляем его
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
	send_string(client, msg);
	for (int current = 1; current != maxAttempts; ++current) {
		if (recv_string(client) == "ban") {
			send_string(client, "Password true! You have access to chat.");
			send_string(client, "You have been assigned an id: " + id_client);
			return true;
		}
		else {
			if (current <= maxAttempts) {
				int attempt_left = maxAttempts - current;
				string msg_attempt = to_string(attempt_left) + " attempt(s) left. Try again: ";
				send_string(client, msg_attempt);
			}
		}
	}
	send_string(client, "All attempts are wasted.");
	return false;
}

// Функция для кика пользователя по id (отправляет сообщение и закрывает соединение)
void KickUser(int id) {
	mtx.lock();
	for (auto it = Users_Connected.begin(); it != Users_Connected.end(); ++it) {
		if (it->id == id) {
			send_string(it->socket, "You have been kicked from the server.");
			closesocket(it->socket);
			Users_Connected.erase(it);
			counter--;
			cout << "User with id " << id << " has been kicked." << endl;
			mtx.unlock();
			return;
		}
	}
	mtx.unlock();
	MessageBeep(MB_ICONERROR);
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
		MessageBeep(MB_ICONERROR);
		closesocket(clientsocket);
		return;
	}

	cout << "User " << id_client << " successfully authenticated." << endl;
	MessageBeep(MB_OK);

	// Добавляем пользователя в общий список
	mtx.lock();
	Users_Connected.push_back({ id, clientsocket });
	counter++;
	mtx.unlock();

	// Основной цикл приёма и рассылки сообщений
	while (true) {
		vector<uint64_t> enc_msg_vec = recv(clientsocket);
		if (enc_msg_vec.empty()) {
			cout << "User " << id_client << " disconected or error." << endl;
			MessageBeep(MB_ICONERROR);
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
		string dec_msg = Decrypting_Message(enc_msg_vec);
		cout << "User " << id_client << ": " << dec_msg << endl;
		string full_msg_to_send = id_client + " " + dec_msg;
		vector<uint64_t> enc_msg_for_others = Encrypting_Message(full_msg_to_send);

		mtx.lock();
		for (const auto& user : Users_Connected) {
			if (user.socket != clientsocket && user.socket != INVALID_SOCKET) {
				send(user.socket, enc_msg_for_others);
			}
		}
		// Рассылка сообщения всем остальным пользователям
		mtx.unlock();
	}
}

// Главная функция: инициализация сервера, приём подключений и запуск потоков
int main() {



	WSAData wsadata;
	WORD WinSockVer = MAKEWORD(2, 2);

	// Инициализация WinSock
	if (WSAStartup(WinSockVer, &wsadata) != 0) {
		cout << "Error" << endl;
		MessageBeep(MB_ICONERROR);
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
	if (bind(slisten, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		cout << "Bind ERROR." << endl;
		MessageBeep(MB_ICONERROR);
	}
	if (listen(slisten, SOMAXCONN) == SOCKET_ERROR) {
		cout << "Listen ERROR." << endl;
		MessageBeep(MB_ICONERROR);
	}
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
				MessageBeep(MB_ICONERROR);
			}
		}
		}).detach();

	// Основной цикл: приём новых подключений и запуск потоков для клиентов
	while (true) {
		newconnection = accept(slisten, (SOCKADDR*)&addr, &size_of_len);

		if (newconnection == INVALID_SOCKET) {
			cout << "User is not connected." << endl;
			MessageBeep(MB_ICONERROR);
		}
		else {
			cout << "New User attempting to connect." << endl;
			MessageBeep(MB_OK);
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


static vector<uint64_t> Encrypting_Message(string msg) {
	vector<uint64_t> encrypt_msg;

	int sum = 0;
	for (char c : msg) {
		if (c == ' ') sum++;
	}
	sum = (sum == 0) ? 1 : sum;


	encrypt_msg.push_back(power(static_cast<uint64_t>(sum), e, n));//добавление в вектор количество пробелов
	for (unsigned char c : msg) {
		encrypt_msg.push_back(encrypt(c, sum));//добавление самого зашифрованного сообщения
	}
	return encrypt_msg; //возвращение ветктора
}

static string Decrypting_Message(const vector<uint64_t>& enc_msg) {
	string dec_msg;
	if (enc_msg.size() < 1) {
		return "";
	}
	uint64_t val = power(enc_msg[0], d, n);//определение числа(количества пробелов)
	int offset = static_cast<int>(val);

	for (size_t i = 1; i < enc_msg.size(); ++i) {
		dec_msg += static_cast<char>(decrypt(enc_msg[i], offset));//дешифровка сообщения
	}
	return dec_msg;
}

static char decrypt(uint64_t x, int volume) {
	uint64_t res = power(x, d, n);
	return static_cast<unsigned char>(res - volume);
}

static uint64_t encrypt(unsigned char x, int volume) {
	return power(static_cast<uint64_t>(x) + volume, e, n);
}