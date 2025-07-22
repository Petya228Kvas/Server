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

vector<SOCKET> Users_Connected;

mutex mtx;
int counter = 0;

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

void send(SOCKET client, string msg) {
	size_t msg_size_send = msg.size();
	send(client, (char*)&msg_size_send, sizeof(int), NULL);
	send(client, msg.c_str(), msg_size_send, NULL);
}


bool RecvPassword(SOCKET client) {
	const int maxAttempts = 4;
	
	stringstream ss;
	ss << this_thread::get_id();
	int id;
	ss >> id;
	string id_client = to_string(id);

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

void ClientHandler(SOCKET clientsocket) {

	stringstream ss;
	ss << this_thread::get_id();
	int id;
	ss >> id;
	string id_client = to_string(id);

	if (!RecvPassword(clientsocket)) {
		cout << "Authentication failed for " << id_client << ". Closing connection." << endl;
		closesocket(clientsocket);
		return;
	}

	cout << "User " << id_client << " successfully authenticated." << endl;

	mtx.lock();
	Users_Connected.push_back(clientsocket);
	counter++;
	mtx.unlock();


	while (true) {
		int msg_size = 0;
		int result = recv(clientsocket, (char*)&msg_size, sizeof(int), NULL);//принятие размера сообщения
		if (result <= 0) {
			cout << "User " << id_client << " disconected or error." << endl;
			mtx.lock();
			for (auto it = Users_Connected.begin(); it != Users_Connected.end(); ++it) {
				if (*it == clientsocket) {
					Users_Connected.erase(it);
					break;
				}
			}
			counter--;
			mtx.unlock();
			closesocket(clientsocket);
			break;
		}
		char* msg = new char[msg_size + 1];//выделение памяти под сообщение
		msg[msg_size] = '\0';// для конца строки
		result = recv(clientsocket, msg, msg_size, NULL);//Принятие самого сообщения ///////Точка ошибки
		if (result <= 0) {
			cout << "User " << id_client << " disconected or error." << endl;
			mtx.lock();
			for (auto it = Users_Connected.begin(); it != Users_Connected.end(); ++it) {
				if (*it == clientsocket) {
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
		mtx.lock();
		for (SOCKET other_client : Users_Connected) {
			if (other_client == clientsocket) continue;
			if (other_client == INVALID_SOCKET) continue;
			send(other_client, id_client + ":");
			send(other_client, (char*)&msg_size, sizeof(int), NULL);//отправка размера сообщения
			send(other_client, msg, msg_size, NULL);//отправка сообщения
		}
		mtx.unlock();
		delete[] msg;
	}
}





int main() {

	WSAData wsadata;
	WORD WinSockVer = MAKEWORD(2, 2);

	if (WSAStartup(WinSockVer, &wsadata) != 0) {
		cout << "Error" << endl;
		exit(1);
	}

	SOCKADDR_IN addr;
	int size_of_len = sizeof(addr);
	addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(7777);
	addr.sin_family = AF_INET;

	SOCKET slisten = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (bind(slisten, (SOCKADDR*)&addr, sizeof(addr)) == SOCKET_ERROR)
		cout<< "Bind ERROR."<<endl;
	if (listen(slisten, SOMAXCONN) == SOCKET_ERROR)
		cout << "Listen ERROR." << endl;
	cout << "Server start listen client..." << endl;

	SOCKET newconnection;
	vector<thread> client_threads;
	
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

	WaitForMultipleObjects(counter, NULL, TRUE, INFINITY);
	closesocket(slisten);
	WSACleanup();


	return 0;
}