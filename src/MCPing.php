<?php

namespace MCServerStatus;

use Exception;
use MCServerStatus\Exceptions\MCPingException;
use MCServerStatus\Responses\MCPingResponse;

class MCPing
{

	private static $socket;
	private static $timeout;
	private static $response;

	private function __construct()
	{
	}

	public static function check($hostname = '127.0.0.1', $port = 25565, $timeout = 2, $isOld17 = false)
	{

		self::$response = new MCPingResponse();

		try {
			self::$response->hostname = $hostname;

			if (!is_int($port) || $port < 1024 || $port > 65535) {
				throw new MCPingException('Invalid port');
			}
			self::$response->port = $port;

			if (!is_int($timeout) || $timeout < 0) {
				throw new MCPingException('Invalid timeout');
			}
			self::$timeout = $timeout;

			if (!is_bool($isOld17)) {
				throw new MCPingException('Invalid parameter in $isold17');
			}

			if (filter_var(self::$response->hostname, FILTER_VALIDATE_IP)) {
				self::$response->address = self::$response->hostname;
			} else {
				$resolvedIP = gethostbyname(self::$response->hostname);

				if (filter_var($resolvedIP, FILTER_VALIDATE_IP)) {
					self::$response->address = $resolvedIP;
				} else {
					$dns = @dns_get_record('_minecraft._tcp.' . self::$response->hostname, DNS_SRV);

					if (!$dns) {
						throw new MCPingException('dns_get_record(): A temporary server error occurred');
					}

					if (is_array($dns) and count($dns) > 0) {
						self::$response->address = gethostbyname($dns[0]['target']);
						self::$response->port = $dns[0]['port'];
					}
				}
			}

			self::$socket = @fsockopen(self::$response->address, self::$response->port, $errno, $errstr, self::$timeout);
			if (!self::$socket) {
				throw new MCPingException("Failed to connect or create a socket: $errstr");
			}
			stream_set_timeout(self::$socket, self::$timeout);

			if (!$isOld17) {
				self::ping();
			} else {
				self::pingOld();
			}

			self::$response->online = true;
		} catch (MCPingException $e) {
			self::$response->error = $e->getMessage();
		} catch (Exception $e) {
			self::$response->error = $e->getMessage();
		} finally {
			@fclose(self::$socket);
		}

		return self::$response;
	}

	private static function ping()
	{

		$timestart = microtime(true);

		$data = "\x00";
		$data .= "\x04";
		$data .= pack('c', strlen(self::$response->hostname)) . self::$response->hostname;
		$data .= pack('n', self::$response->port);
		$data .= "\x01";
		$data = pack('c', strlen($data)) . $data;

		fwrite(self::$socket, $data);

		$startPing = microtime(true);
		fwrite(self::$socket, "\x01\x00");

		$length = self::readVarInt();
		if ($length < 10) {
			throw new MCPingException('Response length not valid');
		}

		fgetc(self::$socket);

		$length = self::readVarInt();
		$data = "";
		do {
			if (microtime(true) - $timestart > self::$timeout) {
				throw new MCPingException('Server read timed out');
			}
			$remainder = $length - strlen($data);
			$block = fread(self::$socket, $remainder);

			if (!$block) {
				throw new MCPingException('Server returned too few data');
			}
			$data .= $block;
		} while (strlen($data) < $length);

		self::$response->ping = round((microtime(true) - $startPing) * 1000);

		if ($data === false) {
			throw new MCPingException('Server didn\'t return any data');
		}

		$data = json_decode($data, true);

		if (json_last_error() !== JSON_ERROR_NONE) {
			throw new MCPingException(json_last_error_msg());
		}

		self::$response->version = $data['version']['name'];
		self::$response->protocol = $data['version']['protocol'];
		self::$response->players = $data['players']['online'];
		self::$response->max_players = $data['players']['max'];
		self::$response->sample_player_list = self::createSamplePlayerList(@$data['players']['sample']);
		self::$response->motd = self::createMotd($data['description']);
		self::$response->favicon = isset($data['favicon']) ? $data['favicon'] : null;
		self::$response->mods = isset($data['modinfo']) ? $data['modinfo'] : null;
	}

	private static function pingOld()
	{
		fwrite(self::$socket, "\xFE\x01");

		$startPing = microtime(true);

		$data = fread(self::$socket, 512);
		self::$response->ping = round((microtime(true) - $startPing) * 1000);

		$length = strlen($data);
		if ($length < 4 || $data[0] !== "\xFF") {
			throw new MCPingException('$length < 4 || $data[ 0 ] !== "\xFF"');
		}

		$data = substr($data, 3);
		$data = iconv('UTF-16BE', 'UTF-8', $data);

		if ($data[1] === "\xA7" && $data[2] === "\x31") {
			$data = explode("\x00", $data);
			self::$response->motd = $data[3];
			self::$response->players = intval($data[4]);
			self::$response->max_players = intval($data[5]);
			self::$response->protocol = intval($data[1]);
			self::$response->version = $data[2];
		} else {
			$data = explode("\xA7", $data);
			self::$response->motd = substr($data[0], 0, -1);
			self::$response->players = isset($data[1]) ? intval($data[1]) : 0;
			self::$response->max_players = isset($data[2]) ? intval($data[2]) : 0;
			self::$response->protocol = 0;
			self::$response->version = '1.3';
		}
	}

	private static function readVarInt()
	{
		$i = 0;
		$j = 0;

		while (true) {
			$k = @fgetc(self::$socket);
			if ($k === false) {
				return 0;
			}
			$k = ord($k);
			$i |= ($k & 0x7F) << $j++ * 7;
			if ($j > 5) {
				throw new MCPingException('VarInt too big');
			}
			if (($k & 0x80) != 128) {
				break;
			}
		}

		return $i;
	}

	private static function createSamplePlayerList($obj)
	{
		return (isset($obj) && is_array($obj) && count($obj) > 0) ? $obj : null;
	}

	private static function createMotd($string)
	{
		if (!is_array($string)) {
			return $string;
		} elseif (isset($string['extra'])) {
			$output = '';

			foreach ($string['extra'] as $item) {
				if (is_array($item)) {
					if (isset($item['text'])) {
						$output .= $item['text'];
					}
					if (isset($item['color'])) {
						switch ($item['color']) {
							case 'black':
								$output .= '§0';
								break;
							case 'dark_blue':
								$output .= '§1';
								break;
							case 'dark_green':
								$output .= '§2';
								break;
							case 'dark_aqua':
								$output .= '§3';
								break;
							case 'dark_red':
								$output .= '§4';
								break;
							case 'dark_purple':
								$output .= '§5';
								break;
							case 'gold':
								$output .= '§6';
								break;
							case 'gray':
								$output .= '§7';
								break;
							case 'dark_gray':
								$output .= '§8';
								break;
							case 'blue':
								$output .= '§9';
								break;
							case 'green':
								$output .= '§a';
								break;
							case 'aqua':
								$output .= '§b';
								break;
							case 'red':
								$output .= '§c';
								break;
							case 'light_purple':
								$output .= '§d';
								break;
							case 'yellow':
								$output .= '§e';
								break;
							case 'white':
								$output .= '§f';
								break;
						}
					}
					if (isset($item['obfuscated'])) {
						$output .= '§k';
					}
					if (isset($item['bold'])) {
						$output .= '§l';
					}
					if (isset($item['strikethrough'])) {
						$output .= '§m';
					}
					if (isset($item['underline'])) {
						$output .= '§n';
					}
					if (isset($item['italic'])) {
						$output .= '§o';
					}
					if (isset($item['reset'])) {
						$output .= '§r';
					}
				}
			}

			if (isset($string['text'])) {
				$output .= $string['text'];
			}

			return $output;
		} elseif (isset($string['text'])) {
			return $string['text'];
		} else {
			return $string;
		}
	}
}
