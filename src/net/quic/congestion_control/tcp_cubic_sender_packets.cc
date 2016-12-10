// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/quic/congestion_control/tcp_cubic_sender_packets.h"

#include <algorithm>

#include "base/metrics/histogram_macros.h"
#include "net/quic/congestion_control/prr_sender.h"
#include "net/quic/congestion_control/rtt_stats.h"
#include "net/quic/crypto/crypto_protocol.h"
#include "net/quic/proto/cached_network_parameters.pb.h"
#include "net/quic/quic_bug_tracker.h"
#include "net/quic/quic_flags.h"
#include <fstream>
#include <sys/time.h>

using std::max;
using std::min;

namespace net {

namespace {
// Constants based on TCP defaults.
// The minimum cwnd based on RFC 3782 (TCP NewReno) for cwnd reductions on a
// fast retransmission.  The cwnd after a timeout is still 1.
const QuicPacketCount kDefaultMinimumCongestionWindow = 2;

std::ofstream metricas;
timeval tv;
uint64_t segundoInicial = 0;
uint64_t milisegundoInicial = 0;
}  // namespace

TcpCubicSenderPackets::TcpCubicSenderPackets(
    const QuicClock* clock,
    const RttStats* rtt_stats,
    bool reno,
    QuicPacketCount initial_tcp_congestion_window,
    QuicPacketCount max_tcp_congestion_window,
    QuicConnectionStats* stats)
    : TcpCubicSenderBase(clock, rtt_stats, reno, stats),
      cubic_(clock),
      congestion_window_count_(0),
      congestion_window_(initial_tcp_congestion_window),
      min_congestion_window_(kDefaultMinimumCongestionWindow),
      slowstart_threshold_(max_tcp_congestion_window),
      max_tcp_congestion_window_(max_tcp_congestion_window),
      initial_tcp_congestion_window_(initial_tcp_congestion_window),
      initial_max_tcp_congestion_window_(max_tcp_congestion_window),
      min_slow_start_exit_window_(min_congestion_window_) {


	gettimeofday(&tv, 0);
	segundoInicial = tv.tv_sec;
	milisegundoInicial = tv.tv_usec;
	metricas.open ("metricas.txt");
	metricas << "Timestamp;Packet Number;Tamanho Byte;Bytes in Flight;Bandwidth;Congestion Window;Algoritmo;Pacote perdido;Perdidos ao todo;Perdido ignorado;Largest sent\n";
	metricas.close();

}

TcpCubicSenderPackets::~TcpCubicSenderPackets() {}

void TcpCubicSenderPackets::SetCongestionWindowFromBandwidthAndRtt(
    QuicBandwidth bandwidth,
    QuicTime::Delta rtt) {
  QuicPacketCount new_congestion_window =
      bandwidth.ToBytesPerPeriod(rtt) / kDefaultTCPMSS;
  if (FLAGS_quic_no_lower_bw_resumption_limit) {
    // Limit new CWND to be in the range [1, kMaxCongestionWindow].
    congestion_window_ =
        max(min_congestion_window_,
            min(new_congestion_window, kMaxResumptionCongestionWindow));
  } else {
    congestion_window_ =
        max(min(new_congestion_window, kMaxResumptionCongestionWindow),
            kMinCongestionWindowForBandwidthResumption);
  }
	metricas.open ("metricas.txt", std::ios::app);
	metricas << "Setando CWND BWRTT. CWND: " << congestion_window_ << ".\n";
	metricas.close();
}

void TcpCubicSenderPackets::SetCongestionWindowInPackets(
    QuicPacketCount congestion_window) {
  congestion_window_ = congestion_window;

	metricas.open ("metricas.txt", std::ios::app);
	metricas << "Setando CWND: " << congestion_window_ << ".\n";
	metricas.close();
}

void TcpCubicSenderPackets::SetMinCongestionWindowInPackets(
    QuicPacketCount congestion_window) {
  min_congestion_window_ = congestion_window;

	metricas.open ("metricas.txt", std::ios::app);
	metricas << "Minimo CWND: " << min_congestion_window_ << ".\n";
	metricas.close();
}

void TcpCubicSenderPackets::SetNumEmulatedConnections(int num_connections) {
  TcpCubicSenderBase::SetNumEmulatedConnections(num_connections);
  cubic_.SetNumConnections(num_connections_);
}

void TcpCubicSenderPackets::ExitSlowstart() {
  slowstart_threshold_ = congestion_window_;

	metricas.open ("metricas.txt", std::ios::app);
	metricas << "### Saindo do SlowStart ###\n";
	metricas.close();
}

void TcpCubicSenderPackets::OnPacketLost(QuicPacketNumber packet_number,
                                         QuicByteCount lost_bytes,
                                         QuicByteCount bytes_in_flight) {
  // TCP NewReno (RFC6582) says that once a loss occurs, any losses in packets
  // already sent should be treated as a single loss event, since it's expected.
  if (packet_number <= largest_sent_at_last_cutback_) {
    if (last_cutback_exited_slowstart_) {
      ++stats_->slowstart_packets_lost;
      stats_->slowstart_bytes_lost += lost_bytes;
      if (slow_start_large_reduction_) {
        if (stats_->slowstart_packets_lost == 1 ||
            (stats_->slowstart_bytes_lost / kDefaultTCPMSS) >
                (stats_->slowstart_bytes_lost - lost_bytes) / kDefaultTCPMSS) {
          // Reduce congestion window by 1 for every mss of bytes lost.
          congestion_window_ =
              max(congestion_window_ - 1, min_slow_start_exit_window_);
        }
        slowstart_threshold_ = congestion_window_;
      }
    }
	metricas.open ("metricas.txt", std::ios::app);
	gettimeofday(&tv, 0);
	metricas << tv.tv_sec - segundoInicial << "." << tv.tv_usec << ";"; //timestamp
	metricas << packet_number << ";"; // packet number
	metricas << lost_bytes << ";"; // packet size in bytes
	metricas << bytes_in_flight << ";"; // bytes in flight
	metricas << BandwidthEstimate().ToKBitsPerSecond() << ";"; // bandwidth
	metricas << congestion_window_ << ";"; // cwnd
	metricas << "IGLOSS" << ";;"; // algorithm
	metricas << stats_->tcp_loss_events << ";X;"; // total lost
	metricas << largest_sent_at_last_cutback_ << "\n"; // largest sent
	metricas.close();
    DVLOG(1) << "Ignoring loss for largest_missing:" << packet_number
             << " because it was sent prior to the last CWND cutback.";
    return;
  }

  ++stats_->tcp_loss_events;
  last_cutback_exited_slowstart_ = InSlowStart();
  if (InSlowStart()) {
    ++stats_->slowstart_packets_lost;
  }

  if (!no_prr_) {
    prr_.OnPacketLost(bytes_in_flight);
  }

  // TODO(jri): Separate out all of slow start into a separate class.
  if (slow_start_large_reduction_ && InSlowStart()) {
    DCHECK_LT(1u, congestion_window_);
    if (congestion_window_ >= 2 * initial_tcp_congestion_window_) {
      min_slow_start_exit_window_ = congestion_window_ / 2;
    }
    congestion_window_ = congestion_window_ - 1;
  } else if (reno_) {
    congestion_window_ = congestion_window_ * RenoBeta();
  } else {
    congestion_window_ =
        cubic_.CongestionWindowAfterPacketLoss(congestion_window_);
  }
  // Enforce a minimum congestion window.
  if (congestion_window_ < min_congestion_window_) {
    congestion_window_ = min_congestion_window_;
  }
  slowstart_threshold_ = congestion_window_;
  largest_sent_at_last_cutback_ = largest_sent_packet_number_;
  // reset packet count from congestion avoidance mode. We start
  // counting again when we're out of recovery.
  congestion_window_count_ = 0;

  metricas.open ("metricas.txt", std::ios::app);
  gettimeofday(&tv, 0);
  metricas << tv.tv_sec - segundoInicial << "." << tv.tv_usec << ";"; //timestamp
  metricas << packet_number << ";"; // packet number
  metricas << lost_bytes << ";"; // packet size in bytes
  metricas << bytes_in_flight << ";"; // bytes in flight
  metricas << BandwidthEstimate().ToKBitsPerSecond() << ";"; // bandwidth
  metricas << congestion_window_ << ";";
  metricas << "LOSS" << ";X;"; // algorithm
  metricas << stats_->tcp_loss_events << ";;"; // total lost
  metricas << largest_sent_at_last_cutback_ << "\n"; // largest sent
  metricas.close();

  DVLOG(1) << "Incoming loss; congestion window: " << congestion_window_
           << " slowstart threshold: " << slowstart_threshold_;
}

QuicByteCount TcpCubicSenderPackets::GetCongestionWindow() const {
  return congestion_window_ * kDefaultTCPMSS;
}

QuicByteCount TcpCubicSenderPackets::GetSlowStartThreshold() const {
  return slowstart_threshold_ * kDefaultTCPMSS;
}

// Called when we receive an ack. Normal TCP tracks how many packets one ack
// represents, but quic has a separate ack for each packet.
void TcpCubicSenderPackets::MaybeIncreaseCwnd(
    QuicPacketNumber acked_packet_number,
    QuicByteCount acked_bytes,
    QuicByteCount bytes_in_flight) {
  QUIC_BUG_IF(InRecovery()) << "Never increase the CWND during recovery.";
  // Do not increase the congestion window unless the sender is close to using
  // the current window.

    metricas.open ("metricas.txt", std::ios::app);
    gettimeofday(&tv, 0);
    metricas << tv.tv_sec - segundoInicial << "." << tv.tv_usec << ";"; //timestamp
    metricas << acked_packet_number << ";";
    metricas << acked_bytes << ";"; // packet size in bytes
    metricas << bytes_in_flight << ";";
    metricas << BandwidthEstimate().ToKBitsPerSecond() << ";";
    metricas.close();

  if (!IsCwndLimited(bytes_in_flight)) {
    cubic_.OnApplicationLimited();
    metricas.open ("metricas.txt", std::ios::app);
    metricas << congestion_window_ << ";APPLIM;;;;\n";
    metricas.close();
    return;
  }
  if (congestion_window_ >= max_tcp_congestion_window_) {
	    metricas.open ("metricas.txt", std::ios::app);
	    metricas << congestion_window_ << ";TCPMAX;;;;\n";
	    metricas.close();
    return;
  }
  if (InSlowStart()) {
    // TCP slow start, exponential growth, increase by one for each ACK.
    ++congestion_window_;

    metricas.open ("metricas.txt", std::ios::app);
    metricas << congestion_window_ << ";SS;;;;\n";
    metricas.close();

    DVLOG(1) << "Slow start; congestion window: " << congestion_window_
             << " slowstart threshold: " << slowstart_threshold_;
    return;
  }
  // Congestion avoidance
  if (reno_) {
    // Classic Reno congestion avoidance.
    ++congestion_window_count_;
    // Divide by num_connections to smoothly increase the CWND at a faster
    // rate than conventional Reno.
    if (congestion_window_count_ * num_connections_ >= congestion_window_) {
      ++congestion_window_;
      congestion_window_count_ = 0;
    }

    DVLOG(1) << "Reno; congestion window: " << congestion_window_
             << " slowstart threshold: " << slowstart_threshold_
             << " congestion window count: " << congestion_window_count_;
  } else {
    congestion_window_ = min(max_tcp_congestion_window_,
                             cubic_.CongestionWindowAfterAck(
                                 congestion_window_, rtt_stats_->min_rtt()));

    metricas.open ("metricas.txt", std::ios::app);
    metricas << congestion_window_ << ";CA;;;;\n";
    //metricas << slowstart_threshold_ << "\n";
    metricas.close();

    DVLOG(1) << "Cubic; congestion window: " << congestion_window_
             << " slowstart threshold: " << slowstart_threshold_;
  }

}

void TcpCubicSenderPackets::HandleRetransmissionTimeout() {
  cubic_.Reset();
  slowstart_threshold_ = congestion_window_ / 2;
  congestion_window_ = min_congestion_window_;
}

void TcpCubicSenderPackets::OnConnectionMigration() {
  TcpCubicSenderBase::OnConnectionMigration();
  cubic_.Reset();
  congestion_window_count_ = 0;
  congestion_window_ = initial_tcp_congestion_window_;
  slowstart_threshold_ = initial_max_tcp_congestion_window_;
  max_tcp_congestion_window_ = initial_max_tcp_congestion_window_;
}

CongestionControlType TcpCubicSenderPackets::GetCongestionControlType() const {
  return reno_ ? kReno : kCubic;
}

}  // namespace net
