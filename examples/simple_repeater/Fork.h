#pragma once

#include <ForkFeatures.h>
#include <Mesh.h>
#include <helpers/IdentityStore.h>

class MyMesh;
#ifdef WITH_MQTT_BRIDGE
class MQTTBridge;
#endif

/**
 * \brief  The fork's features, as the one object MyMesh holds.
 *
 * MyMesh calls into this at a handful of points -- begin, the bridge setup, loop,
 * the end of its own command parser -- and every feature hangs off those calls in
 * its own file, compiled only when its switch is on (include/ForkFeatures.h). The
 * features are fixed when the image is built, so the dispatch is static: no table,
 * no registration, nothing on the heap. MyMesh names this class a friend, so the
 * feature code reaches the mesh's own state rather than growing one accessor per
 * field on a file upstream keeps editing.
 */
class Fork {
  MyMesh& _mesh;

public:
  explicit Fork(MyMesh& mesh) : _mesh(mesh) { }

  // After the ACL is loaded: each feature reads its own settings file.
  void begin(FILESYSTEM* fs);
#ifdef WITH_MQTT_BRIDGE
  // Before the bridge starts: anything that must be registered with it first.
  void attachBridge(MQTTBridge* bridge);
#endif
  // Every loop, after the radio.
  void loop();
  // A command upstream's own verbs did not take, before the common CLI sees it.
  // Returns true when a feature answered it in 'reply'.
  bool handleCommand(uint32_t sender_timestamp, char* command, char* reply);
};
